/*
 * NetEnum_RPC - AD-based Passive RPC Service Discovery
 *
 * Discovers RPC services across the domain by querying Active Directory —
 * no direct connections to target hosts, no port scanning.
 *
 * How it works:
 *   Active Directory is a registry of domain services. When a Windows
 *   service registers with the domain it writes a Service Principal Name
 *   (SPN) into its computer/account object. This module reads those SPN
 *   records and infers which RPC services are running on each host, then
 *   cross-references UAC flags and object class to harden the inference.
 *
 * Traffic profile:
 *   One paged LDAP query to the nearest DC — identical to what any
 *   domain-joined workstation sends at logon or Group Policy refresh.
 *   Zero connections to target hosts. EDR on target machines sees nothing.
 *
 * Build: VS 2022+  /analyze  /W4
 * Link:  activeds.lib  adsiid.lib
 *
 * SAL 2.0 enforced by PREfast (/analyze). sal.h included via windows.h.
 */

#include <windows.h>
#include <stdio.h>
#include <activeds.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "activeds.lib")
#pragma comment(lib, "adsiid.lib")


/* ── Configuration ──────────────────────────────────────────────────────── */

/* Keep page size modest — indistinguishable from standard domain traffic. */
#define RPC_PAGE_SIZE       200

/* IPv4/hostname string buffer */
#define RPC_HOST_LEN        256

/* Maximum number of RPC inferences per host */
#define RPC_MAX_PER_HOST    32


/* ── UAC flags relevant to RPC surface inference ────────────────────────── */

#define UAC_ACCOUNTDISABLE          0x00000002
#define UAC_WORKSTATION_TRUST       0x00001000
#define UAC_SERVER_TRUST            0x00002000   /* Domain Controller */
#define UAC_TRUSTED_FOR_DELEGATION  0x00080000
#define UAC_DONT_EXPIRE_PASSWORD    0x00010000


/* ── SPN → RPC service mapping table ────────────────────────────────────── */

/*
 * SpnMap — maps a SPN service-class prefix to a known RPC service.
 *
 * spn_prefix   String that must appear at the start of the SPN value
 *              (case-insensitive). Examples: "HOST/", "WSMAN/", "MSSQLSvc/"
 *
 * rpc_name     Short service identifier for output.
 * rpc_desc     Human-readable description.
 * typical_port Typical port (informational only — not probed).
 * risk         Security relevance note.
 */
typedef struct {
    const char* spn_prefix;
    const char* rpc_name;
    const char* rpc_desc;
    DWORD       typical_port;
    const char* risk;
} SpnMap;

/*
 * SPN-to-RPC mapping table.
 *
 * Sources: MS-RPC documentation, MS-SPNG, common SPN conventions.
 * A HOST/ SPN implies a machine account that accepts authenticated RPC
 * on the standard Windows ports (135, 139, 445).
 */
static const SpnMap s_spnMap[] = {
    { "HOST/",          "HOST-RPC",  "Core Windows RPC (EPMAP/SVCCTL/SAMR)",    135, "Service enumeration, lateral movement" },
    { "WSMAN/",         "WinRM",     "WS-Management RPC over HTTP",             5985, "Remote code execution if misconfigured" },
    { "MSSQLSvc/",      "MSSQL-RPC", "SQL Server named pipes / RPC",            1433, "DB access, Kerberoastable" },
    { "TERMSRV/",       "RDP",       "Remote Desktop (RPC-based session mgmt)", 3389, "Remote access, brute force target" },
    { "ldap/",          "DC-LDAP",   "DC: LDAP + NETLOGON/LSARPC/SAMR",         389, "Domain recon, credential attacks" },
    { "DNS/",           "DNS-RPC",   "DNS Server RPC management interface",      53,  "DNS hijacking if exposed" },
    { "GC/",            "GC-RPC",    "Global Catalog (DC) — full AD RPC set",   3268, "Cross-domain enumeration" },
    { "E3514235-4B06-11D1-AB04-00C04FC2DCD2/", /* repl GUID */
                        "DS-REPL",   "Directory Replication Service (DRS RPC)", 135, "DCSync — high value target" },
    { "RPCSS/",         "RPCSS",     "RPC Sub-System (EPMAP activator)",        135, "DCOM attack surface" },
    { "cifs/",          "CIFS",      "SMB/CIFS → WINREG/SVCCTL over named pipe",445, "Remote registry, service control" },
    { "http/",          "HTTP-RPC",  "IIS / WinRM HTTP endpoint",               80,  "Potential RPC over HTTP proxy" },
    { "FTP/",           "FTP-SVC",   "IIS FTP — shares host with Spooler",      21,  "Print Spooler often co-located" },
};

#define S_SPN_MAP_COUNT  ARRAYSIZE(s_spnMap)


/* ── Per-host RPC inference result ─────────────────────────────────────── */

/*
 * RpcInference — one inferred RPC service on one host.
 *
 * source describes why we believe the service is present:
 *   "SPN"   — explicit SPN record found in AD
 *   "UAC"   — inferred from userAccountControl flags (e.g., DC always has SAMR)
 *   "CLASS" — inferred from objectClass (e.g., computer → EPMAP)
 */
typedef struct {
    char  host[RPC_HOST_LEN];   /* dNSHostName or cn */
    char  rpc_name[64];
    char  rpc_desc[128];
    DWORD typical_port;
    char  risk[128];
    char  source[16];           /* "SPN" | "UAC" | "CLASS" */
    char  matched_spn[256];     /* original SPN string that matched, or "" */
} RpcInference;

/*
 * InferenceList — growable array of RpcInference.
 */
typedef struct {
    RpcInference* items;
    DWORD         count;
    DWORD         capacity;
} InferenceList;


/* ── Forward declarations ───────────────────────────────────────────────── */

_Check_return_ _Ret_maybenull_
static InferenceList* IListAlloc(_In_ DWORD cap);

static void           IListFree(_In_opt_ InferenceList* lst);

static BOOL           IListAdd(_Inout_  InferenceList* lst,
                               _In_z_   const char*    host,
                               _In_z_   const char*    rpc_name,
                               _In_z_   const char*    rpc_desc,
                               _In_     DWORD          port,
                               _In_z_   const char*    risk,
                               _In_z_   const char*    source,
                               _In_z_   const char*    matched_spn);

static void           InferFromSpn(_Inout_  InferenceList* lst,
                                   _In_z_   const char*    host,
                                   _In_z_   const WCHAR*   spn);

static void           InferFromUac(_Inout_  InferenceList* lst,
                                   _In_z_   const char*    host,
                                   _In_     DWORD          uac);

static void           InferFromClass(_Inout_  InferenceList* lst,
                                     _In_z_   const char*    host);

static void           PrintResults(_In_ const InferenceList* lst);

_Must_inspect_result_
_Success_(SUCCEEDED(return))
static HRESULT BuildSearchObject(_Outptr_ IDirectorySearch** ppSearch);

_Must_inspect_result_
_Success_(SUCCEEDED(return))
HRESULT DiscoverRpcViaAD(void);


/* ═══════════════════════════════════════════════════════════════════════════
 * IListAlloc / IListFree / IListAdd
 * Standard growable-array helpers. Same pattern as NetEnum_v2.
 * ═══════════════════════════════════════════════════════════════════════════ */

_Check_return_ _Ret_maybenull_
static InferenceList* IListAlloc(_In_ DWORD cap)
{
    InferenceList* lst = (InferenceList*)malloc(sizeof(InferenceList));
    if (!lst) return NULL;

    lst->items = (RpcInference*)malloc(sizeof(RpcInference) * cap);
    if (!lst->items) { free(lst); return NULL; }

    lst->count    = 0;
    lst->capacity = cap;
    return lst;
}

static void IListFree(_In_opt_ InferenceList* lst)
{
    if (!lst) return;
    free(lst->items);
    free(lst);
}

static BOOL IListAdd(
    _Inout_ InferenceList* lst,
    _In_z_  const char*    host,
    _In_z_  const char*    rpc_name,
    _In_z_  const char*    rpc_desc,
    _In_    DWORD          port,
    _In_z_  const char*    risk,
    _In_z_  const char*    source,
    _In_z_  const char*    matched_spn)
{
    if (lst->count >= lst->capacity) {
        DWORD newcap = lst->capacity * 2;
        RpcInference* grown = (RpcInference*)realloc(
            lst->items, sizeof(RpcInference) * newcap);
        if (!grown) return FALSE;
        lst->items    = grown;
        lst->capacity = newcap;
    }

    RpcInference* e = &lst->items[lst->count++];
    strcpy_s(e->host,        sizeof(e->host),        host);
    strcpy_s(e->rpc_name,    sizeof(e->rpc_name),    rpc_name);
    strcpy_s(e->rpc_desc,    sizeof(e->rpc_desc),    rpc_desc);
    e->typical_port = port;
    strcpy_s(e->risk,        sizeof(e->risk),        risk);
    strcpy_s(e->source,      sizeof(e->source),      source);
    strcpy_s(e->matched_spn, sizeof(e->matched_spn), matched_spn);
    return TRUE;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * InferFromSpn
 *
 * Converts one SPN wide-string value into zero or more RpcInference entries.
 *
 * Algorithm:
 *   Convert SPN to narrow string, then compare against s_spnMap prefixes
 *   (case-insensitive). A match means the host exposes that RPC service.
 *
 * _Inout_  lst   Results appended here.
 * _In_z_   host  DNS hostname of the computer object (narrow).
 * _In_z_   spn   Raw SPN value from AD (wide), e.g. L"MSSQLSvc/db01:1433"
 * ═══════════════════════════════════════════════════════════════════════════ */
static void InferFromSpn(
    _Inout_ InferenceList* lst,
    _In_z_  const char*    host,
    _In_z_  const WCHAR*   spn)
{
    /* Convert SPN to ASCII for comparison */
    char narrow[512];
    if (wcstombs_s(NULL, narrow, sizeof(narrow), spn, _TRUNCATE) != 0)
        return;

    for (DWORD i = 0; i < S_SPN_MAP_COUNT; i++) {
        size_t plen = strlen(s_spnMap[i].spn_prefix);
        if (_strnicmp(narrow, s_spnMap[i].spn_prefix, plen) == 0) {
            IListAdd(lst,
                     host,
                     s_spnMap[i].rpc_name,
                     s_spnMap[i].rpc_desc,
                     s_spnMap[i].typical_port,
                     s_spnMap[i].risk,
                     "SPN",
                     narrow);
        }
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * InferFromUac
 *
 * Derives guaranteed-present RPC services from userAccountControl flags.
 *
 * Logic:
 *   SERVER_TRUST_ACCOUNT (DC) guarantees:  EPMAP, SAMR, LSARPC, NETLOGON,
 *                                           DRS replication RPC.
 *   TRUSTED_FOR_DELEGATION guarantees:      NETLOGON active (Kerberos delegation).
 *   WORKSTATION_TRUST_ACCOUNT implies:      EPMAP, SVCCTL likely present.
 *   ACCOUNTDISABLE:                         Skip — machine is disabled.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void InferFromUac(
    _Inout_ InferenceList* lst,
    _In_z_  const char*    host,
    _In_    DWORD          uac)
{
    if (uac & UAC_ACCOUNTDISABLE) return;   /* Disabled computer — skip */

    if (uac & UAC_SERVER_TRUST) {
        /* Domain Controller — full set of core RPC services guaranteed */
        IListAdd(lst, host, "EPMAP",    "RPC Endpoint Mapper",              135, "Recon pivot",           "UAC", "SERVER_TRUST_ACCOUNT");
        IListAdd(lst, host, "SAMR",     "Security Account Manager",         445, "Account enumeration",   "UAC", "SERVER_TRUST_ACCOUNT");
        IListAdd(lst, host, "LSARPC",   "LSA Remote Procedure Call",        445, "Policy/trust leakage",  "UAC", "SERVER_TRUST_ACCOUNT");
        IListAdd(lst, host, "NETLOGON", "Netlogon (domain trust channel)",  445, "Domain trust abuse",    "UAC", "SERVER_TRUST_ACCOUNT");
        IListAdd(lst, host, "DS-REPL",  "Directory Replication RPC (DRS)",  135, "DCSync target",         "UAC", "SERVER_TRUST_ACCOUNT");
    }

    if (uac & UAC_TRUSTED_FOR_DELEGATION) {
        /* Delegation-enabled: Kerberos + Netlogon RPC active */
        IListAdd(lst, host, "NETLOGON", "Netlogon (delegation path)",       445, "Kerberos delegation abuse", "UAC", "TRUSTED_FOR_DELEGATION");
    }

    if (uac & UAC_WORKSTATION_TRUST) {
        /* Standard workstation/server: EPMAP and Service Control Manager */
        IListAdd(lst, host, "EPMAP",  "RPC Endpoint Mapper",                135, "Service enumeration",   "UAC", "WORKSTATION_TRUST_ACCOUNT");
        IListAdd(lst, host, "SVCCTL", "Service Control Manager",            445, "Service manipulation",  "UAC", "WORKSTATION_TRUST_ACCOUNT");
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * InferFromClass
 *
 * Baseline inference: any computer object in AD has at minimum EPMAP
 * (Windows always starts the RPC runtime). This is the lowest-confidence
 * inference and is tagged "CLASS" so analysts can filter it.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void InferFromClass(
    _Inout_ InferenceList* lst,
    _In_z_  const char*    host)
{
    IListAdd(lst, host, "EPMAP", "RPC Endpoint Mapper (baseline)",
             135, "Always present on Windows", "CLASS", "objectClass=computer");
}


/* ═══════════════════════════════════════════════════════════════════════════
 * PrintResults
 *
 * Renders the inference list to stdout, grouped by host then source
 * confidence tier: SPN (highest) → UAC → CLASS (lowest).
 * ═══════════════════════════════════════════════════════════════════════════ */
static void PrintResults(_In_ const InferenceList* lst)
{
    if (lst->count == 0) {
        printf("  (no RPC services inferred)\n");
        return;
    }

    printf("\n%-40s  %-12s  %-5s  %-10s  %s\n",
           "Host", "Service", "Port", "Source", "Risk");
    printf("%-40s  %-12s  %-5s  %-10s  %s\n",
           "----------------------------------------",
           "------------", "-----", "----------",
           "--------------------------------------------");

    for (DWORD i = 0; i < lst->count; i++) {
        const RpcInference* e = &lst->items[i];
        printf("%-40s  %-12s  %-5lu  %-10s  %s\n",
               e->host, e->rpc_name, e->typical_port,
               e->source, e->risk);

        /* Print matched SPN only for SPN-sourced entries (verbose context) */
        if (strcmp(e->source, "SPN") == 0 && e->matched_spn[0] != '\0')
            printf("  └─ SPN: %s\n", e->matched_spn);
    }

    printf("\nTotal inferences: %lu\n", lst->count);

    /* Confidence summary */
    DWORD nSPN = 0, nUAC = 0, nClass = 0;
    for (DWORD i = 0; i < lst->count; i++) {
        if (strcmp(lst->items[i].source, "SPN")   == 0) nSPN++;
        else if (strcmp(lst->items[i].source, "UAC")   == 0) nUAC++;
        else                                               nClass++;
    }
    printf("  SPN-confirmed : %lu  (highest confidence)\n", nSPN);
    printf("  UAC-inferred  : %lu  (high confidence — AD attributes)\n", nUAC);
    printf("  Class-baseline: %lu  (low confidence — objectClass only)\n", nClass);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * BuildSearchObject
 *
 * Identical to NetEnum_v2 pattern: bind rootDSE → read defaultNamingContext
 * → return IDirectorySearch for that context.
 * Extracted into its own function so DiscoverRpcViaAD stays readable.
 *
 * _Outptr_  ppSearch  Non-NULL on success; NULL on any failure (guaranteed).
 * ═══════════════════════════════════════════════════════════════════════════ */
_Must_inspect_result_
_Success_(SUCCEEDED(return))
static HRESULT BuildSearchObject(_Outptr_ IDirectorySearch** ppSearch)
{
    *ppSearch = NULL;

    HRESULT  hr;
    IADs*    pDSE = NULL;
    VARIANT  var;
    WCHAR    path[512];

    VariantInit(&var);

    hr = ADsGetObject(L"LDAP://rootDSE", &IID_IADs, (void**)&pDSE);
    if (FAILED(hr)) { wprintf(L"[!] rootDSE: 0x%08X\n", hr); goto done; }

    hr = pDSE->lpVtbl->Get(pDSE, L"defaultNamingContext", &var);
    if (FAILED(hr)) { wprintf(L"[!] defaultNamingContext: 0x%08X\n", hr); goto done; }

    swprintf_s(path, ARRAYSIZE(path), L"LDAP://%s", var.bstrVal);
    wprintf(L"[*] Domain: %s\n", path);

    hr = ADsGetObject(path, &IID_IDirectorySearch, (void**)ppSearch);
    if (FAILED(hr)) { wprintf(L"[!] IDirectorySearch: 0x%08X\n", hr); goto done; }

    /* Search preferences: paged, synchronous, subtree */
    ADS_SEARCHPREF_INFO prefs[3];
    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = RPC_PAGE_SIZE;
    prefs[2].dwSearchPref   = ADS_SEARCHPREF_ASYNCHRONOUS;
    prefs[2].vValue.dwType  = ADSTYPE_BOOLEAN;
    prefs[2].vValue.Boolean = FALSE;

    (*ppSearch)->lpVtbl->SetSearchPreference(*ppSearch, prefs, ARRAYSIZE(prefs));

done:
    VariantClear(&var);
    if (pDSE) pDSE->lpVtbl->Release(pDSE);
    if (FAILED(hr) && *ppSearch) {
        (*ppSearch)->lpVtbl->Release(*ppSearch);
        *ppSearch = NULL;
    }
    return hr;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * DiscoverRpcViaAD
 *
 * Main function. Issues one LDAP query for all computer objects, then for
 * each result runs three inference passes:
 *
 *   Pass 1 — SPN    : parse servicePrincipalName multi-value attribute.
 *   Pass 2 — UAC    : decode userAccountControl flags.
 *   Pass 3 — CLASS  : baseline — every computer has EPMAP.
 *
 * LDAP filter:
 *   (objectClass=computer)
 *   Attributes: dNSHostName, cn, userAccountControl, servicePrincipalName
 *
 * This single query is the ENTIRE network footprint of this tool.
 * No connections to any computer other than the nearest DC.
 * ═══════════════════════════════════════════════════════════════════════════ */
_Must_inspect_result_
_Success_(SUCCEEDED(return))
HRESULT DiscoverRpcViaAD(void)
{
    IDirectorySearch* pSearch = NULL;
    HRESULT hr = BuildSearchObject(&pSearch);
    if (FAILED(hr)) return hr;

    /* Query every computer object — request only the fields we need */
    LPWSTR attrs[] = {
        L"dNSHostName",
        L"cn",
        L"userAccountControl",
        L"servicePrincipalName"
    };

    ADS_SEARCH_HANDLE hSearch = NULL;
    hr = pSearch->lpVtbl->ExecuteSearch(
        pSearch,
        L"(objectClass=computer)",
        attrs, ARRAYSIZE(attrs),
        &hSearch);

    if (FAILED(hr)) {
        wprintf(L"[!] ExecuteSearch failed: 0x%08X\n", hr);
        pSearch->lpVtbl->Release(pSearch);
        return hr;
    }

    InferenceList* results = IListAlloc(256);
    if (!results) {
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
        pSearch->lpVtbl->Release(pSearch);
        return E_OUTOFMEMORY;
    }

    printf("\n[*] Querying AD for computer objects and SPNs...\n\n");

    DWORD      computerCount = 0;
    HRESULT    hrRow;
    ADS_SEARCH_COLUMN col;

    while ((hrRow = pSearch->lpVtbl->GetNextRow(pSearch, hSearch))
           != S_ADS_NOMORE_ROWS)
    {
        if (FAILED(hrRow)) break;

        computerCount++;

        /* ── Resolve hostname: prefer dNSHostName, fall back to cn ─────── */
        char host[RPC_HOST_LEN] = { 0 };

        hr = pSearch->lpVtbl->GetColumn(pSearch, hSearch, L"dNSHostName", &col);
        if (SUCCEEDED(hr)) {
            if (col.dwNumValues > 0 && col.pADsValues[0].CaseIgnoreString) {
                wcstombs_s(NULL, host, sizeof(host),
                           col.pADsValues[0].CaseIgnoreString, _TRUNCATE);
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        if (host[0] == '\0') {
            hr = pSearch->lpVtbl->GetColumn(pSearch, hSearch, L"cn", &col);
            if (SUCCEEDED(hr)) {
                if (col.dwNumValues > 0 && col.pADsValues[0].CaseIgnoreString) {
                    wcstombs_s(NULL, host, sizeof(host),
                               col.pADsValues[0].CaseIgnoreString, _TRUNCATE);
                }
                pSearch->lpVtbl->FreeColumn(pSearch, &col);
            }
        }

        if (host[0] == '\0') continue;  /* Cannot identify host — skip */

        /* ── Pass 1: SPN-based inference ────────────────────────────────── */
        hr = pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                                        L"servicePrincipalName", &col);
        if (SUCCEEDED(hr)) {
            for (DWORD j = 0; j < col.dwNumValues; j++) {
                if (col.pADsValues[j].CaseIgnoreString)
                    InferFromSpn(results, host,
                                 col.pADsValues[j].CaseIgnoreString);
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        /* ── Pass 2: UAC-based inference ────────────────────────────────── */
        hr = pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                                        L"userAccountControl", &col);
        if (SUCCEEDED(hr)) {
            if (col.dwNumValues > 0)
                InferFromUac(results, host, (DWORD)col.pADsValues[0].Integer);
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        /* ── Pass 3: Class baseline ─────────────────────────────────────── */
        InferFromClass(results, host);
    }

    pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    pSearch->lpVtbl->Release(pSearch);

    printf("[*] Computers in AD: %lu\n", computerCount);

    PrintResults(results);

    IListFree(results);
    return S_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * wmain
 *
 * Initialises COM (COINIT_APARTMENTTHREADED), runs discovery, tears down.
 * ═══════════════════════════════════════════════════════════════════════════ */
int wmain(
    _In_             int      argc,
    _In_reads_(argc) wchar_t* argv[])
{
    (void)argc; (void)argv;

    printf("NetEnum_RPC — Passive RPC Discovery via Active Directory\n");
    printf("Zero connections to target hosts. One LDAP query to DC.\n\n");

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        wprintf(L"[!] COM init failed: 0x%08X\n", hr);
        return 1;
    }

    hr = DiscoverRpcViaAD();

    if (FAILED(hr))
        wprintf(L"\n[!] Failed: 0x%08X\n", hr);
    else
        printf("\n[*] Done.\n");

    CoUninitialize();
    return SUCCEEDED(hr) ? 0 : 1;
}
