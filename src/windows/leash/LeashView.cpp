//*****************************************************************************
// File:	LeashView.cpp
// By:		Arthur David Leather
// Created:	12/02/98
// Copyright	@1998 Massachusetts Institute of Technology - All rights reserved.
// Description:	CPP file for LeashView.h. Contains variables and functions
//		for the Leash FormView
//
// History:
//
// MM/DD/YY	Inits	Description of Change
// 12/02/98	ADL		Original
// 20030508     JEA     Added
//*****************************************************************************

#include "stdafx.h"
#include <afxpriv.h>
#include "Leash.h"
#include "LeashDoc.h"
#include "LeashView.h"
#include "MainFrm.h"
#include "reminder.h"
#include "lglobals.h"
#include "LeashDebugWindow.h"
#include "LeashMessageBox.h"
#include "LeashAboutBox.h"
#include "Krb4Properties.h"
#include "Krb5Properties.h"
#include "LeashProperties.h"
#include "KrbProperties.h"
#include "AfsProperties.h"
#include <krb5.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static CHAR THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CLeashView

IMPLEMENT_DYNCREATE(CLeashView, CListView)

BEGIN_MESSAGE_MAP(CLeashView, CListView)
	//{{AFX_MSG_MAP(CLeashView)
    ON_MESSAGE(WM_WARNINGPOPUP, OnWarningPopup)
	ON_MESSAGE(WM_GOODBYE, OnGoodbye)
    ON_MESSAGE(WM_TRAYICON, OnTrayIcon)
    ON_NOTIFY(TVN_ITEMEXPANDED, IDC_TREEVIEW, OnItemexpandedTreeview)
	ON_WM_CREATE()
	ON_WM_SHOWWINDOW()
	ON_COMMAND(ID_INIT_TICKET, OnInitTicket)
	ON_COMMAND(ID_RENEW_TICKET, OnRenewTicket)
    ON_COMMAND(ID_IMPORT_TICKET, OnImportTicket)
	ON_COMMAND(ID_DESTROY_TICKET, OnDestroyTicket)
	ON_COMMAND(ID_CHANGE_PASSWORD, OnChangePassword)
	ON_COMMAND(ID_UPDATE_DISPLAY, OnUpdateDisplay)
	ON_COMMAND(ID_SYN_TIME, OnSynTime)
	ON_COMMAND(ID_DEBUG_MODE, OnDebugMode)
	ON_COMMAND(ID_LARGE_ICONS, OnLargeIcons)
	ON_COMMAND(ID_TIME_ISSUED, OnTimeIssued)
    ON_COMMAND(ID_VALID_UNTIL, OnValidUntil)
	ON_COMMAND(ID_RENEWABLE_UNTIL, OnRenewableUntil)
    ON_COMMAND(ID_SHOW_TICKET_FLAGS, OnShowTicketFlags)
    ON_COMMAND(ID_ENCRYPTION_TYPE, OnEncryptionType)
    ON_UPDATE_COMMAND_UI(ID_TIME_ISSUED, OnUpdateTimeIssued)
    ON_UPDATE_COMMAND_UI(ID_VALID_UNTIL, OnUpdateValidUntil)
    ON_UPDATE_COMMAND_UI(ID_RENEWABLE_UNTIL, OnUpdateRenewableUntil)
    ON_UPDATE_COMMAND_UI(ID_SHOW_TICKET_FLAGS, OnUpdateShowTicketFlags)
    ON_UPDATE_COMMAND_UI(ID_ENCRYPTION_TYPE, OnUpdateEncryptionType)
	ON_COMMAND(ID_UPPERCASE_REALM, OnUppercaseRealm)
	ON_COMMAND(ID_KILL_TIX_ONEXIT, OnKillTixOnExit)
    ON_UPDATE_COMMAND_UI(ID_UPPERCASE_REALM, OnUpdateUppercaseRealm)
    ON_UPDATE_COMMAND_UI(ID_KILL_TIX_ONEXIT, OnUpdateKillTixOnExit)
	ON_WM_DESTROY()
	ON_UPDATE_COMMAND_UI(ID_DESTROY_TICKET, OnUpdateDestroyTicket)
    ON_UPDATE_COMMAND_UI(ID_IMPORT_TICKET, OnUpdateImportTicket)
	ON_UPDATE_COMMAND_UI(ID_INIT_TICKET, OnUpdateInitTicket)
	ON_UPDATE_COMMAND_UI(ID_RENEW_TICKET, OnUpdateRenewTicket)
	ON_COMMAND(ID_APP_ABOUT, OnAppAbout)
	ON_COMMAND(ID_AFS_CONTROL_PANEL, OnAfsControlPanel)
	ON_UPDATE_COMMAND_UI(ID_DEBUG_MODE, OnUpdateDebugMode)
	ON_UPDATE_COMMAND_UI(ID_CFG_FILES, OnUpdateCfgFiles)
	ON_COMMAND(ID_KRB4_PROPERTIES, OnKrb4Properties)
	ON_COMMAND(ID_KRB5_PROPERTIES, OnKrb5Properties)
	ON_COMMAND(ID_LEASH_PROPERTIES, OnLeashProperties)
    ON_COMMAND(ID_LEASH_RESTORE, OnLeashRestore)
    ON_COMMAND(ID_LEASH_MINIMIZE, OnLeashMinimize)
	ON_COMMAND(ID_LOW_TICKET_ALARM, OnLowTicketAlarm)
	ON_COMMAND(ID_AUTO_RENEW, OnAutoRenew)
	ON_UPDATE_COMMAND_UI(ID_LOW_TICKET_ALARM, OnUpdateLowTicketAlarm)
	ON_UPDATE_COMMAND_UI(ID_AUTO_RENEW, OnUpdateAutoRenew)
	ON_UPDATE_COMMAND_UI(ID_KRB4_PROPERTIES, OnUpdateKrb4Properties)
	ON_UPDATE_COMMAND_UI(ID_KRB5_PROPERTIES, OnUpdateKrb5Properties)
	ON_UPDATE_COMMAND_UI(ID_AFS_CONTROL_PANEL, OnUpdateAfsControlPanel)
	ON_COMMAND(ID_PROPERTIES, OnKrbProperties)
	ON_UPDATE_COMMAND_UI(ID_PROPERTIES, OnUpdateProperties)
	ON_COMMAND(ID_HELP_KERBEROS_, OnHelpKerberos)
	ON_COMMAND(ID_HELP_LEASH32, OnHelpLeash32)
	ON_COMMAND(ID_HELP_WHYUSELEASH32, OnHelpWhyuseleash32)
	ON_WM_SIZE()
	ON_WM_LBUTTONDOWN()
	ON_WM_CLOSE()
	ON_WM_HSCROLL()
	ON_WM_VSCROLL()
    ON_WM_SYSCOLORCHANGE()
    ON_MESSAGE(ID_OBTAIN_TGT_WITH_LPARAM, OnObtainTGTWithParam)
    ON_NOTIFY(HDN_ITEMCHANGED, 0, OnItemChanged)
	//}}AFX_MSG_MAP

END_MESSAGE_MAP()


time_t CLeashView::m_ticketTimeLeft = 0;  // # of seconds left before tickets expire
INT  CLeashView::m_forwardableTicket = 0;
INT  CLeashView::m_proxiableTicket = 0;
INT  CLeashView::m_renewableTicket = 0;
INT  CLeashView::m_noaddressTicket = 0;
DWORD CLeashView::m_publicIPAddress = 0;
INT  CLeashView::m_ticketStatusAfs = 0; // Defense Condition: are we low on tickets?
INT  CLeashView::m_ticketStatusKrb4 = 0; // Defense Condition: are we low on tickets?
INT  CLeashView::m_ticketStatusKrb5 = 0; // Defense Condition: are we low on tickets?
INT  CLeashView::m_warningOfTicketTimeLeftAfs = 0; // Prevents warning box from coming up repeatively
INT  CLeashView::m_warningOfTicketTimeLeftKrb4 = 0; // Prevents warning box from coming up repeatively
INT  CLeashView::m_warningOfTicketTimeLeftKrb5 = 0; // Prevents warning box from coming up repeatively
INT  CLeashView::m_warningOfTicketTimeLeftLockAfs = 0;
INT  CLeashView::m_warningOfTicketTimeLeftLockKrb4 = 0;
INT  CLeashView::m_warningOfTicketTimeLeftLockKrb5 = 0;
INT  CLeashView::m_updateDisplayCount;
INT  CLeashView::m_alreadyPlayedDisplayCount;
INT  CLeashView::m_autoRenewTickets = 0;
BOOL CLeashView::m_lowTicketAlarmSound;
INT  CLeashView::m_autoRenewalAttempted = 0;
BOOL CLeashView::m_importedTickets = 0;
LONG CLeashView::m_timerMsgNotInProgress = 1;
ViewColumnInfo CLeashView::sm_viewColumns[] =
{
    {"Principal", true, -1, 100},                        // PRINCIPAL
    {"Issued", false, ID_TIME_ISSUED, 100},              // TIME_ISSUED
    {"Renewable Until", false, ID_RENEWABLE_UNTIL, 100}, // RENEWABLE_UNTIL
    {"Valid Until", true, ID_VALID_UNTIL, 100},          // VALID_UNTIL
    {"Encryption Type", false, ID_ENCRYPTION_TYPE, 100}, // ENCRYPTION_TYPE
    {"Flags", false, ID_SHOW_TICKET_FLAGS, 100},         // TICKET_FLAGS
};


bool change_icon_size = true;
#ifndef KRB5_TC_NOTICKET
extern HANDLE m_tgsReqMutex;
#endif

void krb5TimestampToFileTime(krb5_timestamp t, LPFILETIME pft)
{
    // Note that LONGLONG is a 64-bit value
    LONGLONG ll;

    ll = Int32x32To64(t, 10000000) + 116444736000000000;
    pft->dwLowDateTime = (DWORD)ll;
    pft->dwHighDateTime = ll >> 32;
}

// allocate outstr
void krb5TimestampToLocalizedString(krb5_timestamp t, LPTSTR *outStr)
{
    FILETIME ft, lft;
    SYSTEMTIME st;
    krb5TimestampToFileTime(t, &ft);
    FileTimeToLocalFileTime(&ft, &lft);
    FileTimeToSystemTime(&lft, &st);
    TCHAR timeFormat[80]; // 80 is max required for LOCALE_STIMEFORMAT
    GetLocaleInfo(LOCALE_SYSTEM_DEFAULT,
                  LOCALE_STIMEFORMAT,
                  timeFormat,
                  sizeof(timeFormat) / sizeof(timeFormat[0]));

    int timeSize = GetTimeFormat(LOCALE_SYSTEM_DEFAULT,
                                 TIME_NOSECONDS,
                                 &st,
                                 timeFormat,
                                 NULL,
                                 0);
    // Using dateFormat prevents localization of Month/day order,
    // but there is no other way AFAICT to suppress the year
    TCHAR * dateFormat = "MMM dd'  '";
    int dateSize = GetDateFormat(LOCALE_SYSTEM_DEFAULT,
        0, // flags
        &st,
        dateFormat, // format
        NULL, // date string
        0);

    if (*outStr)
        free(*outStr);

    // Allocate string for combined date and time,
    // but only need one terminating NULL
    LPTSTR str = (LPTSTR) malloc((dateSize + timeSize - 1) *
                 sizeof(TCHAR));
    if (!str) {
        // LeashWarn allocation failure
        *outStr = NULL;
        return;
    }
    GetDateFormat(LOCALE_SYSTEM_DEFAULT,
        0, // flags
        &st,
        dateFormat, // format
        &str[0],
        dateSize);

    GetTimeFormat(LOCALE_SYSTEM_DEFAULT,
                    TIME_NOSECONDS,
                    &st,
                    timeFormat,
                    &str[dateSize - 1],
                    timeSize);
    *outStr = str;
}

/////////////////////////////////////////////////////////////////////////////
// CLeashView construction/destruction

CLeashView::CLeashView()
{
////@#+Need removing as well!
#ifndef NO_KRB4
    m_listKrb4 = NULL;
#endif
    m_listKrb5 = NULL;
    m_listAfs = NULL;
    m_startup = TRUE;
    m_warningOfTicketTimeLeftKrb4 = 0;
    m_warningOfTicketTimeLeftKrb5 = 0;
    m_warningOfTicketTimeLeftLockKrb4 = 0;
    m_warningOfTicketTimeLeftLockKrb5 = 0;
    m_largeIcons = 0;
    m_destroyTicketsOnExit = 0;
    m_debugWindow = 0;
    m_upperCaseRealm = 0;
    m_lowTicketAlarm = 0;
    m_importedTickets = 0;

    m_pDebugWindow = NULL;
    m_pDebugWindow = new CLeashDebugWindow(this);
    if (!m_pDebugWindow)
    {
        AfxMessageBox("There is a problem with the Leash Debug Window!",
                   MB_OK|MB_ICONSTOP);
    }

    m_debugStartUp = TRUE;
    m_isMinimum = FALSE;
    m_lowTicketAlarmSound = FALSE;
    m_alreadyPlayed = FALSE;
    ResetTreeNodes();
    m_hMenu = NULL;
    m_pApp = NULL;
    m_forwardableTicket = 0;
    m_proxiableTicket = 0;
    m_renewableTicket = 0;
    m_noaddressTicket = 0;
    m_publicIPAddress = 0;
    m_autoRenewTickets = 0;
    m_autoRenewalAttempted = 0;
    m_pWarningMessage = NULL;
    m_bIconAdded = FALSE;
    m_bIconDeleted = FALSE;
#ifndef KRB5_TC_NOTICKET
    m_tgsReqMutex = CreateMutex(NULL, FALSE, NULL);
#endif
}


CLeashView::~CLeashView()
{
#ifndef KRB5_TC_NOTICKET
    CloseHandle(m_tgsReqMutex);
#endif
    // destroys window if not already destroyed
    if (m_pDebugWindow)
        delete m_pDebugWindow;
}

void CLeashView::OnItemChanged(NMHDR* pNmHdr, LRESULT* pResult)
{
    NMHEADER* pHdr = (NMHEADER*)pNmHdr;
    if (!pHdr->pitem)
        return;
    if (!pHdr->pitem->mask & HDI_WIDTH)
        return;

    // Sync column width and save to registry
    for (int i=0, columnIndex=0; i<NUM_VIEW_COLUMNS; i++) {
        ViewColumnInfo &info = sm_viewColumns[i];
        if ((info.m_enabled) && (columnIndex++ == pHdr->iItem)) {
            info.m_columnWidth = pHdr->pitem->cxy;
            if (m_pApp)
                m_pApp->WriteProfileInt("ColumnWidths", info.m_name, info.m_columnWidth);
            break;
        }
    }
}

BOOL CLeashView::PreCreateWindow(CREATESTRUCT& cs)
{
    // TODO: Modify the Window class or styles here by modifying
    //  the CREATESTRUCT cs

    return CListView::PreCreateWindow(cs);
}

/////////////////////////////////////////////////////////////////////////////
// CLeashView diagnostics

#ifdef _DEBUG
VOID CLeashView::AssertValid() const
{
    CListView::AssertValid();
}

VOID CLeashView::Dump(CDumpContext& dc) const
{
    CListView::Dump(dc);
}

/*
LeashDoc* CLeashView::GetDocument() // non-debug version is inline
{
    ASSERT(m_pDocument->IsKindOf(RUNTIME_CLASS(LeashDoc)));
    return (LeashDoc*)m_pDocument;
}
*/
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CLeashView message handlers

BOOL CLeashView::Create(LPCTSTR lpszClassName, LPCTSTR lpszWindowName,
                        DWORD dwStyle, const RECT& rect, CWnd* pParentWnd,
                        UINT nID, CCreateContext* pContext)
{
    return CListView::Create(lpszClassName, lpszWindowName, dwStyle, rect,
                             pParentWnd, nID, pContext);
}

INT CLeashView::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
    if (CListView::OnCreate(lpCreateStruct) == -1)
        return -1;
    return 0;
}

VOID CLeashView::OnClose(void)
{
    printf("OnClose\n");
}

time_t CLeashView::LeashTime()
{
    _tzset();
    return time(0);
}

// Call while possessing a lock to ticketinfo.lockObj
INT CLeashView::GetLowTicketStatus(int ver)
{
    BOOL b_notix = (ver == 4 && !ticketinfo.Krb4.btickets) ||
                   (ver == 5 && !ticketinfo.Krb5.btickets) ||
                   (ver == 1 && !ticketinfo.Afs.btickets);

    if (b_notix)
        return NO_TICKETS;

    if (m_ticketTimeLeft <= 0L)
        return ZERO_MINUTES_LEFT;

    if (m_ticketTimeLeft <= 20 * 60)
        return (INT)(m_ticketTimeLeft / 5 / 60) + 2 -
            (m_ticketTimeLeft % (5 * 60) == 0 ? 1 : 0);

    return PLENTY_OF_TIME;
}

VOID CLeashView::UpdateTicketTime(TICKETINFO& ti)
{
    if (!ti.btickets)
    {
        m_ticketTimeLeft = 0L;
        return;
    }

    m_ticketTimeLeft = ti.issue_date + ti.lifetime -
        LeashTime();

    if (m_ticketTimeLeft <= 0L)
        ti.btickets = EXPIRED_TICKETS;
}


VOID CALLBACK EXPORT CLeashView::TimerProc(HWND hWnd, UINT nMsg,
                                           UINT_PTR nIDEvent, DWORD dwTime)
{
    // All of the work is being done in the PreTranslateMessage method
    // in order to have access to the object
}

VOID  CLeashView::ApplicationInfoMissingMsg()
{
    AfxMessageBox("There is a problem finding Leash application information!",
               MB_OK|MB_ICONSTOP);
}

VOID CLeashView::OnShowWindow(BOOL bShow, UINT nStatus)
{
    CListView::OnShowWindow(bShow, nStatus);

    // Get State of Icons Size
    m_pApp = AfxGetApp();
    if (!m_pApp)
    {
        ApplicationInfoMissingMsg();
    }
    else
    {
        m_largeIcons = m_pApp->GetProfileInt("Settings", "LargeIcons", ON);

        // Get State of Destroy Tickets On Exit
        m_destroyTicketsOnExit = m_pApp->GetProfileInt("Settings", "DestroyTicketsOnExit", OFF);

        // Get State of Low Ticket Alarm
        m_lowTicketAlarm = m_pApp->GetProfileInt("Settings", "LowTicketAlarm", ON);

        // Get State of Auto Renew Tickets
        m_autoRenewTickets = m_pApp->GetProfileInt("Settings", "AutoRenewTickets", ON);

        // Get State of Upper Case Realm
        m_upperCaseRealm = pLeash_get_default_uppercaserealm();

        // Forwardable flag
        m_forwardableTicket = pLeash_get_default_forwardable();

        // Proxiable flag
        m_proxiableTicket = pLeash_get_default_proxiable();

        // Renewable flag
        m_renewableTicket = pLeash_get_default_renewable();

        // No Address flag
        m_noaddressTicket = pLeash_get_default_noaddresses();

        // Public IP Address
        m_publicIPAddress = pLeash_get_default_publicip();

        // UI main display column widths
        for (int i=0; i<NUM_VIEW_COLUMNS; i++) {
            ViewColumnInfo &info = sm_viewColumns[i];
            info.m_enabled = m_pApp->GetProfileInt("Settings",
                                                   info.m_name,
                                                   info.m_enabled);
            info.m_columnWidth = m_pApp->GetProfileInt("ColumnWidths",
                                                   info.m_name,
                                                   info.m_columnWidth);
        }

        OnLargeIcons();
    }

    SetTimer(1, ONE_SECOND, TimerProc);

    if (
////
#ifndef NO_KRB4
	!CLeashApp::m_hKrb4DLL &&
#endif
	!CLeashApp::m_hKrb5DLL && !CLeashApp::m_hAfsDLL)
    {
////Update not to mention K4
        AfxMessageBox("Neither Kerberos Four, Kerberos Five nor AFS is loaded!!!"
                   "\r\nYou will not be able to retrieve tickets and/or "
                   "tokens.",
                   MB_OK|MB_ICONWARNING);
    }

    if (!CLeashApp::m_hAfsDLL)
    {
        // No AFS installed
        SetDlgItemText(IDC_LABEL_KERB_TICKETS,
                       "Your Kerberos Tickets (Issued/Expires/[Renew]/Principal)");
    } else
    {
        // AFS installed
        SetDlgItemText(IDC_LABEL_KERB_TICKETS,
                       "Your Kerberos Tickets and AFS Tokens (Issued/Expires/[Renew]/Principal)");

    }

    // CLeashApp::m_krbv5_context = NULL;
}

VOID CLeashView::OnInitTicket()
{
    try {
        InitTicket(m_hWnd);
    }
    catch(...) {
        AfxMessageBox("Ticket Getting operation already in progress", MB_OK, 0);
    }
}

UINT CLeashView::InitTicket(void * hWnd)
{
#ifndef KRB5_TC_NOTICKET
    if (WaitForSingleObject( m_tgsReqMutex, INFINITE ) != WAIT_OBJECT_0)
        throw("Unable to lock TGS request mutex");
#endif
    m_importedTickets = 0;

    LSH_DLGINFO_EX ldi;
    char username[64];
    char realm[192];
    int i=0, j=0;
    if (WaitForSingleObject( ticketinfo.lockObj, INFINITE ) != WAIT_OBJECT_0) {
#ifndef KRB5_TC_NOTICKET
        ReleaseMutex(m_tgsReqMutex);
#endif
        throw("Unable to lock ticketinfo");
    }

    char * principal = ticketinfo.Krb5.principal;
    if (!*principal)
        principal = ticketinfo.Krb4.principal;
    for (; principal[i] && principal[i] != '@'; i++)
    {
        username[i] = principal[i];
    }
    username[i] = '\0';
    if (principal[i]) {
        for (i++ ; principal[i] ; i++, j++)
        {
            realm[j] = principal[i];
        }
    }
    realm[j] = '\0';
    ReleaseMutex(ticketinfo.lockObj);

    ldi.size = sizeof(ldi);
    ldi.dlgtype = DLGTYPE_PASSWD;
    ldi.title = ldi.in.title;
    strcpy(ldi.in.title,"Get Ticket");
    ldi.username = ldi.in.username;
    strcpy(ldi.in.username,username);
    ldi.realm = ldi.in.realm;
    strcpy(ldi.in.realm,realm);
    ldi.dlgtype = DLGTYPE_PASSWD;
    ldi.use_defaults = 1;

    if (!hWnd)
    {
        AfxMessageBox("There is a problem finding the Leash Window!",
                   MB_OK|MB_ICONSTOP);
#ifndef KRB5_TC_NOTICKET
        ReleaseMutex(m_tgsReqMutex);
#endif
        return 0;
    }

#ifndef KRB5_TC_NOTICKET
    ReleaseMutex(m_tgsReqMutex);
#endif
    int result = pLeash_kinit_dlg_ex((HWND)hWnd, &ldi);

    if (-1 == result)
    {
        AfxMessageBox("There is a problem getting tickets!",
                   MB_OK|MB_ICONSTOP);
    }
    else if ( result )
    {
#ifndef KRB5_TC_NOTICKET
        if (WaitForSingleObject( m_tgsReqMutex, INFINITE ) != WAIT_OBJECT_0)
            throw("Unable to lock TGS request mutex");
#endif
        if (WaitForSingleObject( ticketinfo.lockObj, INFINITE ) != WAIT_OBJECT_0) {
#ifndef KRB5_TC_NOTICKET
            ReleaseMutex(m_tgsReqMutex);
#endif
            throw("Unable to lock ticketinfo");
        }
        ticketinfo.Krb4.btickets = GOOD_TICKETS;
        m_warningOfTicketTimeLeftKrb4 = 0;
        m_warningOfTicketTimeLeftKrb5 = 0;
        m_ticketStatusKrb4 = 0;
        m_ticketStatusKrb5 = 0;
        ReleaseMutex(ticketinfo.lockObj);
        m_autoRenewalAttempted = 0;
#ifndef KRB5_TC_NOTICKET
        ReleaseMutex(m_tgsReqMutex);
#endif
        ::SendMessage((HWND)hWnd, WM_COMMAND, ID_UPDATE_DISPLAY, 0);
    }
    return 0;
}

VOID CLeashView::OnImportTicket()
{
    try {
        ImportTicket(m_hWnd);
    }
    catch(...) {
        AfxMessageBox("Ticket Getting operation already in progress", MB_OK|MB_ICONWARNING, 0);
    }
}

UINT CLeashView::ImportTicket(void * hWnd)
{
    if ( !CLeashApp::m_hKrb5DLL )
        return 0;

#ifndef KRB5_TC_NOTICKET
    if (WaitForSingleObject( m_tgsReqMutex, INFINITE ) != WAIT_OBJECT_0)
        throw("Unable to lock TGS request mutex");
#endif
    int import = 0;
    int warning = 0;

    krb5_error_code code;
    krb5_ccache mslsa_ccache=0;
    krb5_principal princ = 0;
    char * pname = 0;
    LONG krb5Error = 0;
    TicketList * tlist = NULL;

    if (code = pkrb5_cc_resolve(CLeashApp::m_krbv5_context, "MSLSA:", &mslsa_ccache))
        goto cleanup;

    if (code = pkrb5_cc_get_principal(CLeashApp::m_krbv5_context, mslsa_ccache, &princ))
        goto cleanup;

    if (code = pkrb5_unparse_name(CLeashApp::m_krbv5_context, princ, &pname))
        goto cleanup;

    if (WaitForSingleObject( ticketinfo.lockObj, INFINITE ) != WAIT_OBJECT_0) {
#ifndef KRB5_TC_NOTICKET
        ReleaseMutex(m_tgsReqMutex);
#endif
        throw("Unable to lock ticketinfo");
    }
    krb5Error = pLeashKRB5GetTickets( &ticketinfo.Krb5, &tlist,
                                      &CLeashApp::m_krbv5_context);
    if ( tlist )
        pLeashFreeTicketList(&tlist);

    warning = strcmp(ticketinfo.Krb5.principal, pname) && ticketinfo.Krb5.btickets;
    ReleaseMutex(ticketinfo.lockObj);

  cleanup:
    if (pname)
        pkrb5_free_unparsed_name(CLeashApp::m_krbv5_context, pname);

    if (princ)
        pkrb5_free_principal(CLeashApp::m_krbv5_context, princ);

    if (mslsa_ccache)
        pkrb5_cc_close(CLeashApp::m_krbv5_context, mslsa_ccache);

    if ( code == 0 ) {
        if (warning)
        {
            INT whatToDo;
#ifndef KRB5_TC_NOTICKET
            ReleaseMutex(m_tgsReqMutex);
#endif
            if (!CLeashApp::m_hAfsDLL
////@#+Need to rework this logic. I am confused what !m_hKrb4DLL means in this case!
#ifndef NO_KRB4
		|| !CLeashApp::m_hKrb4DLL
#endif
		)
                whatToDo = AfxMessageBox("You are about to replace your existing ticket(s)\n"
                                          "with a ticket imported from the Windows credential cache!",
                                          MB_OKCANCEL, 0);
            else
                whatToDo = AfxMessageBox("You are about to replace your existing ticket(s)/token(s)"
                                          "with ticket imported from the Windows credential cache!",
                                          MB_OKCANCEL, 0);
#ifndef KRB5_TC_NOTICKET
            if (WaitForSingleObject( m_tgsReqMutex, INFINITE ) != WAIT_OBJECT_0)
                throw("Unable to lock tgsReqMutex");
#endif
            if (whatToDo == IDOK)
            {
                pLeash_kdestroy();
                import = 1;
            }
        } else {
            import = 1;
        }

        if ( import ) {
            int result = pLeash_import();
            if (-1 == result)
            {
#ifndef KRB5_TC_NOTICKET
                ReleaseMutex(m_tgsReqMutex);
#endif
                AfxMessageBox("There is a problem importing tickets!",
                               MB_OK|MB_ICONSTOP);
                ::SendMessage((HWND)hWnd,WM_COMMAND, ID_UPDATE_DISPLAY, 0);
                m_importedTickets = 0;
            }
            else
            {
                if (WaitForSingleObject( ticketinfo.lockObj, INFINITE ) != WAIT_OBJECT_0) {
#ifndef KRB5_TC_NOTICKET
                    ReleaseMutex(m_tgsReqMutex);
#endif
                    throw("Unable to lock ticketinfo");
                }
                ticketinfo.Krb4.btickets = GOOD_TICKETS;
                ticketinfo.Krb5.btickets = GOOD_TICKETS;
                m_warningOfTicketTimeLeftKrb4 = 0;
                m_warningOfTicketTimeLeftKrb5 = 0;
                m_ticketStatusKrb4 = 0;
                m_ticketStatusKrb5 = 0;
                ReleaseMutex(ticketinfo.lockObj);
#ifndef KRB5_TC_NOTICKET
                ReleaseMutex(m_tgsReqMutex);
#endif
                ::SendMessage((HWND)hWnd, WM_COMMAND, ID_UPDATE_DISPLAY, 0);

#ifndef KRB5_TC_NOTICKET
                if (WaitForSingleObject( m_tgsReqMutex, INFINITE ) != WAIT_OBJECT_0)
                    throw("Unable to lock tgsReqMutex");
#endif
                if (WaitForSingleObject( ticketinfo.lockObj, INFINITE ) != WAIT_OBJECT_0) {
#ifndef KRB5_TC_NOTICKET
                    ReleaseMutex(m_tgsReqMutex);
#endif
                    throw("Unable to lock ticketinfo");
                }
#ifndef KRB5_TC_NOTICKET
                ReleaseMutex(m_tgsReqMutex);
#endif

                if (ticketinfo.Krb5.btickets != GOOD_TICKETS) {
                    ReleaseMutex(ticketinfo.lockObj);
                    AfxBeginThread(InitTicket,hWnd);
                } else {
                    ReleaseMutex(ticketinfo.lockObj);
                    m_importedTickets = 1;
                    m_autoRenewalAttempted = 0;
                }
            }
        }
#ifndef KRB5_TC_NOTICKET
        else {
            ReleaseMutex(m_tgsReqMutex);
        }
#endif
    }
#ifndef KRB5_TC_NOTICKET
    else {
        ReleaseMutex(m_tgsReqMutex);
    }
#endif
    return 0;
}

VOID CLeashView::OnRenewTicket()
{
    if ( !CLeashApp::m_hKrb5DLL )
        return;

    try {
        RenewTicket(m_hWnd);
    }
    catch(...) {
        AfxMessageBox("Ticket Getting operation already in progress", MB_OK|MB_ICONWARNING, 0);
    }
}

UINT CLeashView::RenewTicket(void * hWnd)
{
    if ( !CLeashApp::m_hKrb5DLL )
        return 0;

#ifndef KRB5_TC_NOTICKET
    if (WaitForSingleObject( m_tgsReqMutex, INFINITE ) != WAIT_OBJECT_0)
        throw("Unable to lock TGS request mutex");
#endif

    // Try to renew
    BOOL b_renewed = pLeash_renew();
    TicketList * tlist = NULL;
    if (WaitForSingleObject( ticketinfo.lockObj, INFINITE ) != WAIT_OBJECT_0) {
#ifndef KRB5_TC_NOTICKET
        ReleaseMutex(m_tgsReqMutex);
#endif
        throw("Unable to lock ticketinfo");
    }
    LONG krb5Error = pLeashKRB5GetTickets(&ticketinfo.Krb5, &tlist,
                                           &CLeashApp::m_krbv5_context);
    pLeashFreeTicketList(&tlist);
    if ( b_renewed ) {
        if (!krb5Error && ticketinfo.Krb5.btickets == GOOD_TICKETS) {
            ticketinfo.Krb4.btickets = GOOD_TICKETS;
            m_warningOfTicketTimeLeftKrb4 = 0;
            m_warningOfTicketTimeLeftKrb5 = 0;
            m_ticketStatusKrb4 = 0;
            m_ticketStatusKrb5 = 0;
            m_autoRenewalAttempted = 0;
            ReleaseMutex(ticketinfo.lockObj);
#ifndef KRB5_TC_NOTICKET
            ReleaseMutex(m_tgsReqMutex);
#endif
            ::SendMessage((HWND)hWnd, WM_COMMAND, ID_UPDATE_DISPLAY, 0);
            return 0;
        }
    }

    krb5_error_code code;
    krb5_ccache mslsa_ccache=0;
    krb5_principal princ = 0;
    char * pname = 0;

    if (code = pkrb5_cc_resolve(CLeashApp::m_krbv5_context, "MSLSA:", &mslsa_ccache))
        goto cleanup;

    if (code = pkrb5_cc_get_principal(CLeashApp::m_krbv5_context, mslsa_ccache, &princ))
        goto cleanup;

    if (code = pkrb5_unparse_name(CLeashApp::m_krbv5_context, princ, &pname))
        goto cleanup;

    if ( !strcmp(ticketinfo.Krb5.principal, pname) )
        m_importedTickets = 1;

  cleanup:
    ReleaseMutex(ticketinfo.lockObj);

    if (pname)
        pkrb5_free_unparsed_name(CLeashApp::m_krbv5_context, pname);

    if (princ)
        pkrb5_free_principal(CLeashApp::m_krbv5_context, princ);

    if (mslsa_ccache)
        pkrb5_cc_close(CLeashApp::m_krbv5_context, mslsa_ccache);

#ifndef KRB5_TC_NOTICKET
    ReleaseMutex(m_tgsReqMutex);
#endif
    // If imported from Kerberos LSA, re-import
    // Otherwise, init the tickets
    if ( m_importedTickets )
        AfxBeginThread(ImportTicket,hWnd);
    else
        AfxBeginThread(InitTicket,hWnd);

    return 0;
}

VOID CLeashView::OnDestroyTicket()
{
    if (WaitForSingleObject( ticketinfo.lockObj, INFINITE ) != WAIT_OBJECT_0)
        throw("Unable to lock ticketinfo");
    BOOL b_destroy =ticketinfo.Krb4.btickets || ticketinfo.Krb5.btickets || ticketinfo.Afs.btickets;
    ReleaseMutex(ticketinfo.lockObj);

    if (b_destroy)
    {
        INT whatToDo;

        if (!CLeashApp::m_hAfsDLL)
            whatToDo = AfxMessageBox("Are you sure you want to destroy these tickets?",
                                     MB_ICONEXCLAMATION|MB_YESNO, 0);
        else
            whatToDo = AfxMessageBox("You are about to destroy your ticket(s)/token(s)!",
                                     MB_ICONEXCLAMATION|MB_YESNO, 0);

        if (whatToDo == IDYES)
        {
            pLeash_kdestroy();
            ResetTreeNodes();
            SendMessage(WM_COMMAND, ID_UPDATE_DISPLAY, 0);
        }
    }
    m_importedTickets = 0;
    m_autoRenewalAttempted = 0;
}

VOID CLeashView::OnChangePassword()
{
    if (!m_hWnd)
    {
        AfxMessageBox("There is a problem finding the Leash Window!",
                   MB_OK|MB_ICONSTOP);
        return;
    }

    if (WaitForSingleObject( ticketinfo.lockObj, INFINITE ) != WAIT_OBJECT_0)
        throw("Unable to lock ticketinfo");

    LSH_DLGINFO_EX ldi;
    char username[64];
    char realm[192];
    char * principal = ticketinfo.Krb5.principal;
    if (!*principal)
	principal = ticketinfo.Krb4.principal;
    int i=0, j=0;
    for (; principal[i] && principal[i] != '@'; i++)
    {
	username[i] = principal[i];
    }
    username[i] = '\0';
    if (principal[i]) {
	for (i++ ; principal[i] ; i++, j++)
	{
	    realm[j] = principal[i];
	}
    }
    realm[j] = '\0';
    ReleaseMutex(ticketinfo.lockObj);

    ldi.size = sizeof(ldi);
    ldi.dlgtype = DLGTYPE_CHPASSWD;
    ldi.title = ldi.in.title;
    strcpy(ldi.in.title,"Change Password");
    ldi.username = ldi.in.username;
    strcpy(ldi.in.username,username);
    ldi.realm = ldi.in.realm;
    strcpy(ldi.in.realm,realm);
    ldi.use_defaults = 1;

    int result = pLeash_changepwd_dlg_ex(m_hWnd, &ldi);
    if (-1 == result)
    {
        AfxMessageBox("There is a problem changing password!",
                   MB_OK|MB_ICONSTOP);
    }
}

VOID CLeashView::OnUpdateDisplay()
{
    BOOL AfsEnabled = m_pApp->GetProfileInt("Settings", "AfsStatus", 1);

    CListCtrl& list = GetListCtrl();
    list.DeleteAllItems();
    ModifyStyle(LVS_TYPEMASK, LVS_REPORT);
	UpdateWindow();
    // Delete all of the columns.
    while (list.DeleteColumn(0));

    list.SetImageList(&m_imageList, LVSIL_SMALL);

    // Reconstruct based on current options
    int columnIndex = 0;
    int itemIndex = 0;
    for (int i=0; i<NUM_VIEW_COLUMNS; i++) {
        ViewColumnInfo &info = sm_viewColumns[i];
        if (info.m_enabled) {
            list.InsertColumn(columnIndex++,
                (info.m_name), // @LOCALIZEME!
                LVCFMT_LEFT,
                info.m_columnWidth,
                itemIndex++);
        }
    }

#ifndef NO_KRB4
    INT ticketIconStatusKrb4;
    INT ticketIconStatus_SelectedKrb4;
    INT iconStatusKrb4;
#endif

    INT ticketIconStatusKrb5;
    INT ticketIconStatus_SelectedKrb5;
    INT iconStatusKrb5;

    INT ticketIconStatusAfs;
    INT ticketIconStatus_SelectedAfs;
    INT iconStatusAfs;

#ifndef NO_KRB4
    LONG krb4Error;
#endif
    LONG krb5Error;
    LONG afsError;

    if (WaitForSingleObject( ticketinfo.lockObj, 100 ) != WAIT_OBJECT_0)
        throw("Unable to lock ticketinfo");

#ifndef NO_KRB4
    // Get Kerb 4 tickets in list
    krb4Error = pLeashKRB4GetTickets(&ticketinfo.Krb4, &m_listKrb4);
#endif

    // Get Kerb 5 tickets in list
    krb5Error = pLeashKRB5GetTickets(&ticketinfo.Krb5, &m_listKrb5,
                                     &CLeashApp::m_krbv5_context);
    if (!krb5Error || krb5Error == KRB5_FCC_NOFILE)
    {
        if (CLeashApp::m_hKrb5DLL && !CLeashApp::m_krbv5_profile)
        {
            CHAR confname[MAX_PATH];
            if (CLeashApp::GetProfileFile(confname, sizeof(confname)))
            {
                AfxMessageBox("Can't locate Kerberos Five Config. file!",
                           MB_OK|MB_ICONSTOP);
            }

            const char *filenames[2];
            filenames[0] = confname;
            filenames[1] = NULL;
            pprofile_init(filenames, &CLeashApp::m_krbv5_profile);
        }
    }

    // Get AFS Tokens in list
    if (CLeashApp::m_hAfsDLL) {
        char * principal;
        if ( ticketinfo.Krb5.principal[0] )
            principal = ticketinfo.Krb5.principal;
        else if ( ticketinfo.Krb4.principal[0] )
            principal = ticketinfo.Krb4.principal;
        else
            principal = "";
        afsError = pLeashAFSGetToken(&ticketinfo.Afs, &m_listAfs, principal);
    }

    /*
     * Update Ticket Status for Krb4 and Krb5 so that we may use their state
     * to select the appropriate Icon for the Parent Node
     */

////Might need to delete dependent stuff as well!!!
#ifndef NO_KRB4
    /* Krb4 */
    UpdateTicketTime(ticketinfo.Krb4);
    m_ticketStatusKrb4 = GetLowTicketStatus(4);
    if (!m_listKrb4 || EXPIRED_TICKETS == ticketinfo.Krb4.btickets ||
         m_ticketStatusKrb4 == ZERO_MINUTES_LEFT)
    {
        ticketIconStatusKrb4 = EXPIRED_CLOCK;
        ticketIconStatus_SelectedKrb4 = EXPIRED_CLOCK;
        iconStatusKrb4 = EXPIRED_TICKET;
    }
    else if (TICKETS_LOW == ticketinfo.Krb4.btickets ||
             m_ticketStatusKrb4 == FIVE_MINUTES_LEFT ||
             m_ticketStatusKrb4 == TEN_MINUTES_LEFT ||
             m_ticketStatusKrb4 == FIFTEEN_MINUTES_LEFT)
    {
        ticketIconStatusKrb4 = LOW_CLOCK;
        ticketIconStatus_SelectedKrb4 = LOW_CLOCK;
        iconStatusKrb4 = LOW_TICKET;
    }
    else if ( CLeashApp::m_hKrb4DLL )
    {
        ticketIconStatusKrb4 = ACTIVE_CLOCK;
        ticketIconStatus_SelectedKrb4 = ACTIVE_CLOCK;
        iconStatusKrb4 = ACTIVE_TICKET;
    } else {
        ticketIconStatusKrb4 = EXPIRED_CLOCK;
        ticketIconStatus_SelectedKrb4 = EXPIRED_CLOCK;
        iconStatusKrb4 = TICKET_NOT_INSTALLED;
    }
#endif


    /* Krb5 */
    UpdateTicketTime(ticketinfo.Krb5);
    m_ticketStatusKrb5 = GetLowTicketStatus(5);
    if (!m_listKrb5 || EXPIRED_TICKETS == ticketinfo.Krb5.btickets ||
         m_ticketStatusKrb5 == ZERO_MINUTES_LEFT)
    {
        ticketIconStatusKrb5 = EXPIRED_CLOCK;
        ticketIconStatus_SelectedKrb5 = EXPIRED_CLOCK;
        iconStatusKrb5 = EXPIRED_TICKET;
    }
    else if (TICKETS_LOW == ticketinfo.Krb5.btickets ||
             m_ticketStatusKrb5 == FIVE_MINUTES_LEFT ||
             m_ticketStatusKrb5 == TEN_MINUTES_LEFT ||
             m_ticketStatusKrb5 == FIFTEEN_MINUTES_LEFT)
    {
        ticketIconStatusKrb5 = LOW_CLOCK;
        ticketIconStatus_SelectedKrb5 = LOW_CLOCK;
        iconStatusKrb5 = LOW_TICKET;
    }
    else if ( CLeashApp::m_hKrb5DLL )
    {
        ticketIconStatusKrb5 = ACTIVE_CLOCK;
        ticketIconStatus_SelectedKrb5 = ACTIVE_CLOCK;
        iconStatusKrb5 = ACTIVE_TICKET;
    } else
    {
        ticketIconStatusKrb5 = EXPIRED_CLOCK;
        ticketIconStatus_SelectedKrb5 = EXPIRED_CLOCK;
        iconStatusKrb5 = TICKET_NOT_INSTALLED;
    }

    /* Afs */
    UpdateTicketTime(ticketinfo.Afs);
    m_ticketStatusAfs = GetLowTicketStatus(1);
    if (!m_listAfs || EXPIRED_TICKETS == ticketinfo.Afs.btickets ||
         m_ticketStatusAfs == ZERO_MINUTES_LEFT)
    {
        ticketIconStatusAfs = EXPIRED_CLOCK;
        ticketIconStatus_SelectedAfs = EXPIRED_CLOCK;
        iconStatusAfs = EXPIRED_TICKET;
    }
    else if (TICKETS_LOW == ticketinfo.Afs.btickets ||
             m_ticketStatusAfs == FIVE_MINUTES_LEFT ||
             m_ticketStatusAfs == TEN_MINUTES_LEFT ||
             m_ticketStatusAfs == FIFTEEN_MINUTES_LEFT)
    {
        ticketIconStatusAfs = LOW_CLOCK;
        ticketIconStatus_SelectedAfs = LOW_CLOCK;
        iconStatusAfs = LOW_TICKET;
    }
    else if ( CLeashApp::m_hAfsDLL )
    {
        ticketIconStatusAfs = ACTIVE_CLOCK;
        ticketIconStatus_SelectedAfs = ACTIVE_CLOCK;
        iconStatusAfs = ACTIVE_TICKET;
    } else
    {
        ticketIconStatusAfs = EXPIRED_CLOCK;
        ticketIconStatus_SelectedAfs = EXPIRED_CLOCK;
        iconStatusAfs = TICKET_NOT_INSTALLED;
    }

    int trayIcon = NONE_PARENT_NODE;
    if (CLeashApp::m_hKrb5DLL && m_listKrb5) {
        switch ( iconStatusKrb5 ) {
        case ACTIVE_TICKET:
            trayIcon = ACTIVE_PARENT_NODE;
            break;
        case LOW_TICKET:
            trayIcon = LOW_PARENT_NODE;
            break;
        case EXPIRED_TICKET:
            trayIcon = EXPIRED_PARENT_NODE;
            break;
        }
    }
    SetTrayIcon(NIM_MODIFY, trayIcon);

    TicketList* tempList = m_listKrb5;
    int iItem = 0;
    TCHAR* localTimeStr=NULL;
    while (tempList)
    {
        list.InsertItem(iItem, tempList->theTicket, 0);

        int iSubItem = 1;
        if (sm_viewColumns[TIME_ISSUED].m_enabled) {
            krb5TimestampToLocalizedString(tempList->issued, &localTimeStr);
            list.SetItemText(iItem, iSubItem++, localTimeStr);
        }
        if (sm_viewColumns[RENEWABLE_UNTIL].m_enabled) {
            if (tempList->renew_until) {
                krb5TimestampToLocalizedString(tempList->renew_until, &localTimeStr);
                list.SetItemText(iItem, iSubItem++, localTimeStr);
            } else {
                list.SetItemText(iItem, iSubItem++, "not renewable");
            }
        }
        if (sm_viewColumns[VALID_UNTIL].m_enabled) {
            krb5TimestampToLocalizedString(tempList->valid_until, &localTimeStr);
            list.SetItemText(iItem, iSubItem++, localTimeStr);
        }
        if (sm_viewColumns[ENCRYPTION_TYPE].m_enabled) {
            list.SetItemText(iItem, iSubItem++, tempList->encTypes);
        }
        if (sm_viewColumns[TICKET_FLAGS].m_enabled) {
            list.SetItemText(iItem, iSubItem++, "ticket flags here");
        }

        tempList = tempList->next;
    }
    if (localTimeStr)
        free(localTimeStr);

    pLeashFreeTicketList(&m_listKrb5);

    // @TODO: AFS-specific here
    if (!afsError && CLeashApp::m_hAfsDLL)
    { // AFS installed

        tempList = m_listAfs;
        while (tempList)
        {
            m_tvinsert.item.pszText = tempList->theTicket;
            tempList = tempList->next;
        }

        pLeashFreeTicketList(&m_listAfs);
    }

    // KILL THIS?!
    if (m_startup)
    {
        //m_startup = FALSE;
        UpdateTicketTime(ticketinfo.Krb4);
    }
    ReleaseMutex(ticketinfo.lockObj);
}

VOID CLeashView::OnSynTime()
{
    LONG returnValue;
    returnValue = pLeash_timesync(1);
}

VOID CLeashView::OnActivateView(BOOL bActivate, CView* pActivateView,
                                CView* pDeactiveView)
{
    UINT check = NULL;

    if (m_alreadyPlayed)
    {
        CListView::OnActivateView(bActivate, pActivateView, pDeactiveView);
        return;
    }

    // The following code has put here because at the time
    // 'checking and unchecking' a menuitem with the
    // 'OnUpdate.....(CCmdUI* pCmdUI) functions' were unreliable
    // in CLeashView -->> Better done in CMainFrame
    if( CLeashApp::m_hProgram != 0 )
    {
        m_hMenu = ::GetMenu(CLeashApp::m_hProgram);
    } else {
        return;
    }

    if (m_hMenu) {
        if (!m_largeIcons)
            check = CheckMenuItem(m_hMenu, ID_LARGE_ICONS, MF_CHECKED);
        else
            check = CheckMenuItem(m_hMenu, ID_LARGE_ICONS, MF_UNCHECKED);

        if( check != MF_CHECKED || check != MF_UNCHECKED )
        {
            m_debugStartUp = 1;
        }

        if (!m_destroyTicketsOnExit)
            check = CheckMenuItem(m_hMenu, ID_KILL_TIX_ONEXIT, MF_UNCHECKED);
        else
            check = CheckMenuItem(m_hMenu, ID_KILL_TIX_ONEXIT, MF_CHECKED);

        if (!m_upperCaseRealm)
            check = CheckMenuItem(m_hMenu, ID_UPPERCASE_REALM, MF_UNCHECKED);
        else
            check = CheckMenuItem(m_hMenu, ID_UPPERCASE_REALM, MF_CHECKED);

        for (int i=0; i<NUM_VIEW_COLUMNS; i++) {
            ViewColumnInfo &info = sm_viewColumns[i];
            if (info.m_id >= 0)
                CheckMenuItem(m_hMenu, info.m_id,
                              info.m_enabled ? MF_CHECKED : MF_UNCHECKED);
        }

        if (!m_lowTicketAlarm)
            CheckMenuItem(m_hMenu, ID_LOW_TICKET_ALARM, MF_UNCHECKED);
        else
            CheckMenuItem(m_hMenu, ID_LOW_TICKET_ALARM, MF_CHECKED);

        if (!m_autoRenewTickets)
            CheckMenuItem(m_hMenu, ID_AUTO_RENEW, MF_UNCHECKED);
        else
            CheckMenuItem(m_hMenu, ID_AUTO_RENEW, MF_CHECKED);

        m_debugWindow = m_pApp->GetProfileInt("Settings", "DebugWindow", 0);
        if (!m_debugWindow)
            check = CheckMenuItem(m_hMenu, ID_DEBUG_MODE, MF_UNCHECKED);
        else
            check = CheckMenuItem(m_hMenu, ID_DEBUG_MODE, MF_CHECKED);
    }
    m_lowTicketAlarmSound = !!m_lowTicketAlarm;
    m_alreadyPlayed = TRUE;
    if (m_pApp)
    {
        m_debugWindow = m_pApp->GetProfileInt("Settings", "DebugWindow", 0);

        if (m_hMenu)
        {
            if (!m_debugWindow)
            {
                CheckMenuItem(m_hMenu, ID_DEBUG_MODE, MF_UNCHECKED);
            }
            else
            {
                CheckMenuItem(m_hMenu, ID_DEBUG_MODE, MF_CHECKED);
            }
        }
    }
    else
    {
        ApplicationInfoMissingMsg();
    }

    m_alreadyPlayed = TRUE;

    if (!CKrbProperties::KrbPropertiesOn)
        SendMessage(WM_COMMAND, ID_UPDATE_DISPLAY, 0);

    if (m_debugStartUp)
    {
        OnDebugMode();
    }

    m_debugStartUp = FALSE;

    CListView::OnActivateView(bActivate, pActivateView, pDeactiveView);
}

////@#+Is this KRB4 only?
VOID CLeashView::OnDebugMode()
{
#ifndef NO_KRB4
    if (!pset_krb_debug)
        return;
#endif

    if (!m_pDebugWindow)
    {
        AfxMessageBox("There is a problem with the Leash Debug Window!",
                   MB_OK|MB_ICONSTOP);
        return;
    }


    // Check all possible 'KRB' system varables, then reset (delete) debug file
    CHAR*  Env[] = {"TEMP", "TMP", "HOME", NULL};
    CHAR** pEnv = Env;
    CHAR debugFilePath[MAX_PATH];
    *debugFilePath = 0;

    while (*pEnv)
    {
        CHAR* ptestenv = getenv(*pEnv);
        if (ptestenv)
        {
            // reset debug file
            strcpy(debugFilePath, ptestenv);
            strcat(debugFilePath, "\\LshDebug.log");
            remove(debugFilePath);
            break;
        }

        pEnv++;
    }

    if (!m_debugStartUp)
    {
        if (m_debugWindow%2 == 0)
            m_debugWindow = ON;
        else
            m_debugWindow = OFF;
    }

    if (!m_pApp)
    {
        ApplicationInfoMissingMsg();
    }
    else if (!m_debugWindow)
    {
        if (m_hMenu)
            CheckMenuItem(m_hMenu, ID_DEBUG_MODE, MF_UNCHECKED);

        m_pApp->WriteProfileInt("Settings", "DebugWindow", FALSE_FLAG);
        m_pDebugWindow->DestroyWindow();
////
#ifndef NO_KRB4
        pset_krb_debug(OFF);
        pset_krb_ap_req_debug(OFF);
#endif
        return;
    }
    else
    {
        if (m_hMenu)
            CheckMenuItem(m_hMenu, ID_DEBUG_MODE, MF_CHECKED);

        m_pApp->WriteProfileInt("Settings", "DebugWindow", TRUE_FLAG);
    }

    // Creates the Debug dialog if not created already
    if (m_pDebugWindow->GetSafeHwnd() == 0)
    { // displays the Debug Window
        m_pDebugWindow->Create(debugFilePath);
    }
}

void CLeashView::ToggleViewColumn(eViewColumn viewOption)
{
    if ((viewOption < 0) || (viewOption >= NUM_VIEW_COLUMNS)) {
        //LeashWarn("ToggleViewColumn(): invalid view option index %i", viewOption);
        return;
    }
    ViewColumnInfo &info = sm_viewColumns[viewOption];
    info.m_enabled = !info.m_enabled;
    if (m_pApp)
        m_pApp->WriteProfileInt("Settings", info.m_name, info.m_enabled);
    OnUpdateDisplay();
}

VOID CLeashView::OnRenewableUntil()
{
    ToggleViewColumn(RENEWABLE_UNTIL);
}

VOID CLeashView::OnUpdateRenewableUntil(CCmdUI *pCmdUI)
{
    pCmdUI->SetCheck(sm_viewColumns[RENEWABLE_UNTIL].m_enabled);
}

VOID CLeashView::OnShowTicketFlags()
{
    ToggleViewColumn(TICKET_FLAGS);
}

VOID CLeashView::OnUpdateShowTicketFlags(CCmdUI *pCmdUI)
{
    pCmdUI->SetCheck(sm_viewColumns[TICKET_FLAGS].m_enabled);
}

VOID CLeashView::OnTimeIssued()
{
    ToggleViewColumn(TIME_ISSUED);
}

VOID CLeashView::OnUpdateTimeIssued(CCmdUI *pCmdUI)
{
    pCmdUI->SetCheck(sm_viewColumns[TIME_ISSUED].m_enabled);
}

VOID CLeashView::OnValidUntil()
{
    ToggleViewColumn(VALID_UNTIL);
}

VOID CLeashView::OnUpdateValidUntil(CCmdUI *pCmdUI)
{
    pCmdUI->SetCheck(sm_viewColumns[VALID_UNTIL].m_enabled);
}

VOID CLeashView::OnEncryptionType()
{
    ToggleViewColumn(ENCRYPTION_TYPE);
}

VOID CLeashView::OnUpdateEncryptionType(CCmdUI *pCmdUI)
{
    pCmdUI->SetCheck(sm_viewColumns[ENCRYPTION_TYPE].m_enabled);
}

VOID CLeashView::OnLargeIcons()
{
    INT x, y, n;

    if (change_icon_size)
    {
        if (m_largeIcons%2 == 0)
            m_largeIcons = ON;
        else
            m_largeIcons = OFF;
    }
    else
    {
        if (m_largeIcons%2 == 0)
            m_largeIcons = OFF;
        else
            m_largeIcons = ON;
    }

    x = y = SMALL_ICONS;

    if (!m_pApp)
        ApplicationInfoMissingMsg();
    else
    {
        if (!m_largeIcons)
        {
            if (m_hMenu)
                CheckMenuItem(m_hMenu, ID_LARGE_ICONS, MF_CHECKED);

            x = y = LARGE_ICONS;

	    if (!m_startup)
	    {
                m_pApp->WriteProfileInt("Settings", "LargeIcons", TRUE_FLAG);
	    }
        }
        else
        {
            if (m_hMenu)
                CheckMenuItem(m_hMenu, ID_LARGE_ICONS, MF_UNCHECKED);

            x = y = SMALL_ICONS;

            if (!m_startup)
            {
                m_pApp->WriteProfileInt("Settings", "LargeIcons", FALSE_FLAG);
            }
        }
    }

    HICON hIcon[IMAGE_COUNT];
    for (n = 0; n < IMAGE_COUNT; n++)
    {
        hIcon[n] = NULL;
    }

    m_imageList.DeleteImageList( );

    UINT bitsPerPixel = GetDeviceCaps( ::GetDC(::GetDesktopWindow()), BITSPIXEL);
    UINT ilcColor;
    if ( bitsPerPixel >= 32 )
        ilcColor = ILC_COLOR32;
    else if ( bitsPerPixel >= 24 )
        ilcColor = ILC_COLOR24;
    else if ( bitsPerPixel >= 16 )
        ilcColor = ILC_COLOR16;
    else if ( bitsPerPixel >= 8 )
        ilcColor = ILC_COLOR8;
    else
        ilcColor = ILC_COLOR;
    m_imageList.Create(x, y, ilcColor | ILC_MASK, IMAGE_COUNT, 1);
    m_imageList.SetBkColor(GetSysColor(COLOR_WINDOW));

    hIcon[ACTIVE_TRAY_ICON] = AfxGetApp()->LoadIcon(IDI_LEASH_TRAY_GOOD);
    hIcon[LOW_TRAY_ICON] = AfxGetApp()->LoadIcon(IDI_LEASH_TRAY_LOW);
    hIcon[EXPIRED_TRAY_ICON] = AfxGetApp()->LoadIcon(IDI_LEASH_TRAY_EXPIRED);
    hIcon[NONE_TRAY_ICON]  = AfxGetApp()->LoadIcon(IDI_LEASH_TRAY_NONE);
    hIcon[ACTIVE_PARENT_NODE] = AfxGetApp()->LoadIcon(IDI_LEASH_PRINCIPAL_GOOD);
    hIcon[LOW_PARENT_NODE] = AfxGetApp()->LoadIcon(IDI_LEASH_PRINCIPAL_LOW);
    hIcon[EXPIRED_PARENT_NODE] = AfxGetApp()->LoadIcon(IDI_LEASH_PRINCIPAL_EXPIRED);
    hIcon[NONE_PARENT_NODE]  = AfxGetApp()->LoadIcon(IDI_LEASH_PRINCIPAL_NONE);
    hIcon[ACTIVE_TICKET] = AfxGetApp()->LoadIcon(IDI_TICKETTYPE_GOOD);
    hIcon[LOW_TICKET] = AfxGetApp()->LoadIcon(IDI_TICKETTYPE_LOW);
    hIcon[EXPIRED_TICKET] = AfxGetApp()->LoadIcon(IDI_TICKETTYPE_EXPIRED);
    hIcon[TICKET_NOT_INSTALLED] = AfxGetApp()->LoadIcon(IDI_TICKETTYPE_NOTINSTALLED);
    hIcon[ACTIVE_CLOCK] = AfxGetApp()->LoadIcon(IDI_TICKET_GOOD);
    hIcon[LOW_CLOCK] = AfxGetApp()->LoadIcon(IDI_TICKET_LOW);
    hIcon[EXPIRED_CLOCK] = AfxGetApp()->LoadIcon(IDI_TICKET_EXPIRED);
    hIcon[TKT_ADDRESS] = AfxGetApp()->LoadIcon(IDI_LEASH_TICKET_ADDRESS);
    hIcon[TKT_SESSION] = AfxGetApp()->LoadIcon(IDI_LEASH_TICKET_SESSION);
    hIcon[TKT_ENCRYPTION] = AfxGetApp()->LoadIcon(IDI_LEASH_TICKET_ENCRYPTION);

    for (n = 0; n < IMAGE_COUNT; n++)
    {
        if ( !hIcon[n] ) {
            AfxMessageBox("Can't find one or more images in the Leash Ticket Tree!",
                        MB_OK|MB_ICONSTOP);
            return;
        }
        m_imageList.Add(hIcon[n]);
    }

    if (!m_startup)
        SendMessage(WM_COMMAND, ID_UPDATE_DISPLAY, 0);
}

VOID CLeashView::OnKillTixOnExit()
{
    m_destroyTicketsOnExit = !m_destroyTicketsOnExit;

    if (m_pApp)
        m_pApp->WriteProfileInt("Settings", "DestroyTicketsOnExit",
                                m_destroyTicketsOnExit);
}

VOID CLeashView::OnUpdateKillTixOnExit(CCmdUI *pCmdUI)
{
    pCmdUI->SetCheck(m_destroyTicketsOnExit);
}

VOID CLeashView::OnUppercaseRealm()
{
    m_upperCaseRealm = !m_upperCaseRealm;

    pLeash_set_default_uppercaserealm(m_upperCaseRealm);
}

VOID CLeashView::OnUpdateUppercaseRealm(CCmdUI *pCmdUI)
{
    // description is now 'allow mixed case', so reverse logic
    pCmdUI->SetCheck(!m_upperCaseRealm);
}

VOID CLeashView::ResetTreeNodes()
{
    m_hPrincipalState = 0;
#ifndef NO_KRB4
    m_hKerb4State = 0;
#endif
    m_hKerb5State = 0;
    m_hAFSState = 0;
}

VOID CLeashView::OnDestroy()
{
    SetTrayIcon(NIM_DELETE);

    CListView::OnDestroy();
    if (WaitForSingleObject( ticketinfo.lockObj, INFINITE ) != WAIT_OBJECT_0)
        throw("Unable to lock ticketinfo");
    BOOL b_destroy = m_destroyTicketsOnExit && (ticketinfo.Krb4.btickets || ticketinfo.Krb5.btickets);
    ReleaseMutex(ticketinfo.lockObj);

    if (b_destroy)
    {
        if (pLeash_kdestroy())
        {
            AfxMessageBox("There is a problem destroying tickets!",
                       MB_OK|MB_ICONSTOP);
        }
    }
}

VOID CLeashView::OnUpdateDestroyTicket(CCmdUI* pCmdUI)
{
    if (!CLeashApp::m_hAfsDLL)
        pCmdUI->SetText("&Destroy Ticket(s)\tCtrl+D");
    else
        pCmdUI->SetText("&Destroy Ticket(s)/Token(s)\tCtrl+D");

    if (WaitForSingleObject( ticketinfo.lockObj, INFINITE ) != WAIT_OBJECT_0)
        throw("Unable to lock ticketinfo");
    BOOL b_enable =!ticketinfo.Krb4.btickets && !ticketinfo.Krb5.btickets && !ticketinfo.Afs.btickets;
    ReleaseMutex(ticketinfo.lockObj);

    if (b_enable)
        pCmdUI->Enable(FALSE);
    else
        pCmdUI->Enable(TRUE);
}

VOID CLeashView::OnUpdateInitTicket(CCmdUI* pCmdUI)
{
    if (!CLeashApp::m_hAfsDLL)
        pCmdUI->SetText("&Get Ticket(s)\tCtrl+T");
    else
        pCmdUI->SetText("&Get Ticket(s)/Token(s)\tCtrl+T");

    if (
////Is this logic correct?
#ifndef NO_KRB4
	!CLeashApp::m_hKrb4DLL &&
#endif
	!CLeashApp::m_hKrb5DLL &&
        !CLeashApp::m_hAfsDLL)
        pCmdUI->Enable(FALSE);
    else
        pCmdUI->Enable(TRUE);
}

VOID CLeashView::OnUpdateRenewTicket(CCmdUI* pCmdUI)
{
    if (!CLeashApp::m_hAfsDLL)
        pCmdUI->SetText("&Renew Ticket(s)\tCtrl+R");
    else
        pCmdUI->SetText("&Renew Ticket(s)/Token(s)\tCtrl+R");

    if (WaitForSingleObject( ticketinfo.lockObj, INFINITE ) != WAIT_OBJECT_0)
        throw("Unable to lock ticketinfo");
    BOOL b_enable = !(
#ifndef NO_KRB4
	ticketinfo.Krb4.btickets ||
#endif
	ticketinfo.Krb5.btickets) ||
////Not sure about the boolean logic here
#ifndef NO_KRB4
                    !CLeashApp::m_hKrb4DLL &&
#endif
		    !CLeashApp::m_hKrb5DLL && !CLeashApp::m_hAfsDLL;
    ReleaseMutex(ticketinfo.lockObj);

    if (b_enable)
        pCmdUI->Enable(FALSE);
    else
        pCmdUI->Enable(TRUE);
}

VOID CLeashView::OnUpdateImportTicket(CCmdUI* pCmdUI)
{
    bool ccIsMSLSA = false;

#ifndef KRB5_TC_NOTICKET
    if (WaitForSingleObject( m_tgsReqMutex, INFINITE ) != WAIT_OBJECT_0)
        throw("Unable to lock TGS request mutex");
#endif
    if (CLeashApp::m_krbv5_context)
    {
        const char *ccName = pkrb5_cc_default_name(CLeashApp::m_krbv5_context);

        if (ccName)
            ccIsMSLSA = !strcmp(ccName, "MSLSA:");
    }

    if (!CLeashApp::m_hKrbLSA || !pLeash_importable() || ccIsMSLSA)
        pCmdUI->Enable(FALSE);
    else
        pCmdUI->Enable(TRUE);
#ifndef KRB5_TC_NOTICKET
    ReleaseMutex(m_tgsReqMutex);
#endif
}

LRESULT CLeashView::OnGoodbye(WPARAM wParam, LPARAM lParam)
{
    m_pDebugWindow->DestroyWindow();
    return 0L;
}

VOID CLeashView::OnLeashRestore()
{
    if ( CMainFrame::m_isMinimum ) {
        CMainFrame * frame = (CMainFrame *)GetParentFrame();
        frame->ShowTaskBarButton(TRUE);
        frame->ShowWindow(SW_SHOWNORMAL);
    }
}

VOID CLeashView::OnLeashMinimize()
{
    if ( !CMainFrame::m_isMinimum ) {
        CMainFrame * frame = (CMainFrame *)GetParentFrame();
        // frame->ShowTaskBarButton(FALSE);
        frame->ShowWindow(SW_HIDE);
        frame->ShowWindow(SW_MINIMIZE);
    }
}

LRESULT CLeashView::OnTrayIcon(WPARAM wParam, LPARAM lParam)
{
    switch ( lParam ) {
    case WM_LBUTTONDOWN:
        if ( CMainFrame::m_isMinimum )
            OnLeashRestore();
        else
            OnLeashMinimize();
        break;
    case WM_RBUTTONDOWN:
        {
            int nFlags;
            CMenu * menu = new CMenu();
            menu->CreatePopupMenu();
            if ( !CMainFrame::m_isMinimum )
                menu->AppendMenu(MF_STRING, ID_LEASH_MINIMIZE, "&Close Leash Window");
            else
                menu->AppendMenu(MF_STRING, ID_LEASH_RESTORE, "&Open Leash Window");
            menu->AppendMenu(MF_SEPARATOR);
            menu->AppendMenu(MF_STRING, ID_INIT_TICKET, "&Get Tickets");
#ifndef KRB5_TC_NOTICKET
            if (WaitForSingleObject( m_tgsReqMutex, INFINITE ) != WAIT_OBJECT_0)
                throw("Unable to lock TGS request mutex");
#endif
            if (WaitForSingleObject( ticketinfo.lockObj, INFINITE ) != WAIT_OBJECT_0)
                throw("Unable to lock ticketinfo");
            if (!(
#ifndef NO_KRB4
		ticketinfo.Krb4.btickets ||
#endif
		ticketinfo.Krb5.btickets) ||
////Not entirely sure about the logic
#ifndef NO_KRB4
                 !CLeashApp::m_hKrb4DLL &&
#endif
		 !CLeashApp::m_hKrb5DLL &&
                 !CLeashApp::m_hAfsDLL)
                nFlags = MF_STRING | MF_GRAYED;
            else
                nFlags = MF_STRING;
            menu->AppendMenu(nFlags, ID_RENEW_TICKET, "&Renew Tickets");
            if (!CLeashApp::m_hKrbLSA || !pLeash_importable())
                nFlags = MF_STRING | MF_GRAYED;
            else
                nFlags = MF_STRING;
            menu->AppendMenu(MF_STRING, ID_IMPORT_TICKET, "&Import Tickets");
            if (!ticketinfo.Krb4.btickets && !ticketinfo.Krb5.btickets && !ticketinfo.Afs.btickets)
                nFlags = MF_STRING | MF_GRAYED;
            else
                nFlags = MF_STRING;
            ReleaseMutex(ticketinfo.lockObj);
#ifndef KRB5_TC_NOTICKET
            ReleaseMutex(m_tgsReqMutex);
#endif
            menu->AppendMenu(MF_STRING, ID_DESTROY_TICKET, "&Destroy Tickets");
            menu->AppendMenu(MF_STRING, ID_CHANGE_PASSWORD, "&Change Password");

            menu->AppendMenu(MF_SEPARATOR);
            if ( m_autoRenewTickets )
                nFlags = MF_STRING | MF_CHECKED;
            else
                nFlags = MF_STRING | MF_UNCHECKED;
            menu->AppendMenu(nFlags, ID_AUTO_RENEW, "&Automatic Ticket Renewal");
            if ( m_lowTicketAlarm )
                nFlags = MF_STRING | MF_CHECKED;
            else
                nFlags = MF_STRING | MF_UNCHECKED;
            menu->AppendMenu(nFlags, ID_LOW_TICKET_ALARM, "&Expiration Alarm");
            menu->AppendMenu(MF_SEPARATOR);
            menu->AppendMenu(MF_STRING, ID_APP_EXIT, "E&xit");
            menu->SetDefaultItem(ID_LEASH_RESTORE);

            POINT pt;
            GetCursorPos(&pt);

	    SetForegroundWindow();
            menu->TrackPopupMenu(TPM_RIGHTALIGN | TPM_RIGHTBUTTON,
                                pt.x, pt.y, GetParentFrame());
	    PostMessage(WM_NULL, 0, 0);
            menu->DestroyMenu();
            delete menu;
        }
        break;
    case WM_MOUSEMOVE:
        // SendMessage(WM_COMMAND, ID_UPDATE_DISPLAY, 0);
        break;
    }
    return 0L;
}

VOID CLeashView::OnAppAbout()
{
    CLeashAboutBox leashAboutBox;
    leashAboutBox.DoModal();
}


VOID CLeashView::OnAfsControlPanel()
{
    CAfsProperties afsProperties;
    afsProperties.DoModal();
}

VOID CLeashView::OnInitialUpdate()
{
    CListView::OnInitialUpdate();
    CLeashApp::m_hProgram = ::FindWindow(_T("LEASH.0WNDCLASS"), NULL);
    EnableToolTips();
}

VOID CLeashView::OnItemexpandedTreeview(NMHDR* pNMHDR, LRESULT* pResult)
{
    NM_TREEVIEW* pNMTreeView = (NM_TREEVIEW*)pNMHDR;

    if (m_hPrincipal == pNMTreeView->itemNew.hItem)
        m_hPrincipalState = pNMTreeView->action;
#ifndef NO_KRB4
    else if (m_hKerb4 == pNMTreeView->itemNew.hItem)
        m_hKerb4State = pNMTreeView->action;
#endif
    else if (m_hKerb5 == pNMTreeView->itemNew.hItem)
        m_hKerb5State = pNMTreeView->action;
    else if (m_hAFS ==  pNMTreeView->itemNew.hItem)
        m_hAFSState =  pNMTreeView->action;

    CMainFrame::m_isBeingResized = TRUE;
    *pResult = 0;
}

VOID CLeashView::OnUpdateDebugMode(CCmdUI* pCmdUI)
{
////
#ifndef NO_KRB4
    if (!pset_krb_debug)
#endif
        pCmdUI->Enable(FALSE);
////
#ifndef NO_KRB4
    else
        pCmdUI->Enable(TRUE);
#endif
}

VOID CLeashView::OnUpdateCfgFiles(CCmdUI* pCmdUI)
{
////
#ifndef NO_KRB4
    if (!pkrb_get_krbconf2)
#endif
        pCmdUI->Enable(FALSE);
////
#ifndef NO_KRB4
    else
        pCmdUI->Enable(TRUE);
#endif
}

VOID CLeashView::OnLeashProperties()
{
    CLeashProperties leashProperties;
    leashProperties.DoModal();
}

VOID CLeashView::OnKrbProperties()
{
    CKrbProperties krbProperties("Kerberos Properties");
    krbProperties.DoModal();
}

VOID CLeashView::OnKrb4Properties()
{
#ifndef NO_KRB4
    CKrb4Properties krb4Properties("Kerberos Four Properties");
    krb4Properties.DoModal();
#endif
}

VOID CLeashView::OnKrb5Properties()
{
    CKrb5Properties krb5Properties("Kerberos Five Properties");
    krb5Properties.DoModal();
}

/*
void CLeashView::GetRowWidthHeight(CDC* pDC, LPCSTR theString, int& nRowWidth,
                                   int& nRowHeight, int& nCharWidth)
{
    TEXTMETRIC tm;

    //CEx29aDoc* pDoc = GetDocument();
	pDC->GetTextMetrics(&tm);
    nCharWidth = tm.tmAveCharWidth + 1;
    nRowWidth = strlen(theString);

    //int nFields = theString.GetLength();

    //for(int i = 0; i < nFields; i++)
    //{
	//    nRowWidth += nCharWidth;
	//}

    nRowWidth *= nCharWidth;
    nRowHeight = tm.tmHeight;
}
*/

void CLeashView::SetTrayText(int nim, CString tip)
{
    if ( (nim == NIM_MODIFY) && (m_bIconDeleted) )
        return;
    if ( (nim == NIM_MODIFY) && (!m_bIconAdded) )
        nim = NIM_ADD;

    if ( (nim != NIM_DELETE) || IsWindow(m_hWnd) )
    {
        NOTIFYICONDATA nid;
        memset (&nid, 0x00, sizeof(NOTIFYICONDATA));
        nid.cbSize = sizeof(NOTIFYICONDATA);
        nid.hWnd = m_hWnd;
        nid.uID = 0;
        nid.uFlags = NIF_MESSAGE | NIF_TIP;
        nid.uCallbackMessage = WM_TRAYICON;
        strncpy(nid.szTip, (LPCTSTR) tip, sizeof(nid.szTip));
        nid.szTip[sizeof(nid.szTip)-1] = '\0';
        Shell_NotifyIcon (nim, &nid);
    }

    if ( nim == NIM_ADD )
        m_bIconAdded = TRUE;
    if ( nim == NIM_DELETE )
        m_bIconDeleted = TRUE;
}

void CLeashView::SetTrayIcon(int nim, int state)
{
    static HICON hIcon[IMAGE_COUNT];
    static BOOL bIconInit = FALSE;

    if ( (nim == NIM_MODIFY) && (m_bIconDeleted) )
        return;
    if ( (nim == NIM_MODIFY) && (!m_bIconAdded) )
        nim = NIM_ADD;

    if ( (nim != NIM_DELETE) || IsWindow(m_hWnd) )
    {
        if ( !bIconInit ) {
            // The state is reported as the parent node value although
            // we want to use the Tray Version of the icons
            hIcon[ACTIVE_PARENT_NODE] = AfxGetApp()->LoadIcon(IDI_LEASH_TRAY_GOOD);
            hIcon[LOW_PARENT_NODE] = AfxGetApp()->LoadIcon(IDI_LEASH_TRAY_LOW);
            hIcon[EXPIRED_PARENT_NODE] = AfxGetApp()->LoadIcon(IDI_LEASH_TRAY_EXPIRED);
            hIcon[NONE_PARENT_NODE]  = AfxGetApp()->LoadIcon(IDI_LEASH_TRAY_NONE);
            bIconInit = TRUE;
        }

        NOTIFYICONDATA nid;
        memset (&nid, 0x00, sizeof(NOTIFYICONDATA));
        nid.cbSize = sizeof(NOTIFYICONDATA);
        nid.hWnd = m_hWnd;
        nid.uID = 0;
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        nid.uCallbackMessage = WM_TRAYICON;
        nid.hIcon = hIcon[state];
        Shell_NotifyIcon (nim, &nid);
    }

    if ( nim == NIM_ADD )
        m_bIconAdded = TRUE;
    if ( nim == NIM_DELETE )
        m_bIconDeleted = TRUE;
}

BOOL CLeashView::PostWarningMessage(const CString& message)
{
    if (m_pWarningMessage)
    {
        return FALSE; // can't post more than one warning at a time
    }
    m_pWarningMessage = new CString(message);
    PostMessage(WM_WARNINGPOPUP);
    return TRUE;
}

LRESULT CLeashView::OnWarningPopup(WPARAM wParam, LPARAM lParam)
{
    CLeashMessageBox leashMessageBox(CMainFrame::m_isMinimum ? GetDesktopWindow() : NULL,
                                        *m_pWarningMessage, 100000);
    leashMessageBox.DoModal();
    delete m_pWarningMessage;
    m_pWarningMessage = NULL;
    return 0L;
}

BOOL CLeashView::PreTranslateMessage(MSG* pMsg)
{
	if ( pMsg->message == ID_OBTAIN_TGT_WITH_LPARAM )
	{
		OutputDebugString("Obtain TGT with LParam\n");
	}

    if ( pMsg->message == WM_TIMER ) {
        try {
        if (InterlockedDecrement(&m_timerMsgNotInProgress) == 0) {

            CString ticketStatusKrb4 = TCHAR(NOT_INSTALLED);
            CString ticketStatusKrb5 = TCHAR(NOT_INSTALLED);
            CString ticketStatusAfs  = TCHAR(NOT_INSTALLED);
            CString strTimeDate;
            CString lowTicketWarningKrb4;
            CString lowTicketWarningKrb5;
            CString lowTicketWarningAfs;

          timer_start:
            if (WaitForSingleObject( ticketinfo.lockObj, 100 ) != WAIT_OBJECT_0)
                throw("Unable to lock ticketinfo");
            if (CLeashApp::m_hKrb5DLL)
            {
                // KRB5
                UpdateTicketTime(ticketinfo.Krb5);

                if (!ticketinfo.Krb5.btickets)
                {
                    ticketStatusKrb5 = "Kerb-5: No Tickets";
                }
                else if (EXPIRED_TICKETS == ticketinfo.Krb5.btickets)
                {
                    ticketStatusKrb5 = "Kerb-5: Expired Ticket(s)";
                    m_ticketTimeLeft = 0;
                    lowTicketWarningKrb5 = "Your Kerberos Five ticket(s) have expired";
                    if (!m_warningOfTicketTimeLeftLockKrb5)
                        m_warningOfTicketTimeLeftKrb5 = 0;
                    m_warningOfTicketTimeLeftLockKrb5 = ZERO_MINUTES_LEFT;
                }
                else
                {
                    m_ticketStatusKrb5 = GetLowTicketStatus(5);
                    switch (m_ticketStatusKrb5)
                    {
                    case TWENTY_MINUTES_LEFT:
                        break;
                    case FIFTEEN_MINUTES_LEFT:
                        ticketinfo.Krb5.btickets = TICKETS_LOW;
                        lowTicketWarningKrb5 = "Less then 15 minutes left on your Kerberos Five ticket(s)";
                        break;
                    case TEN_MINUTES_LEFT:
                        ticketinfo.Krb5.btickets = TICKETS_LOW;
                        lowTicketWarningKrb5 = "Less then 10 minutes left on your Kerberos Five ticket(s)";
                        if (!m_warningOfTicketTimeLeftLockKrb5)
                            m_warningOfTicketTimeLeftKrb5 = 0;
                        m_warningOfTicketTimeLeftLockKrb5 = TEN_MINUTES_LEFT;
                        break;
                    case FIVE_MINUTES_LEFT:
                        ticketinfo.Krb5.btickets = TICKETS_LOW;
                        if (m_warningOfTicketTimeLeftLockKrb5 == TEN_MINUTES_LEFT)
                            m_warningOfTicketTimeLeftKrb5 = 0;
                        m_warningOfTicketTimeLeftLockKrb5 = FIVE_MINUTES_LEFT;
                        lowTicketWarningKrb5 = "Less then 5 minutes left on your Kerberos Five ticket(s)";
                        break;
                    default:
                        m_ticketStatusKrb5 = 0;
                        break;
                    }
                }

                if (CMainFrame::m_isMinimum)
                {
                    // minimized dispay
                    ticketStatusKrb5.Format("Kerb-5: %02d:%02d Left",
                                             (m_ticketTimeLeft / 60L / 60L),
                                             (m_ticketTimeLeft / 60L % 60L));
                }
                else
                {
                    // normal display
                    if (GOOD_TICKETS == ticketinfo.Krb5.btickets || TICKETS_LOW == ticketinfo.Krb5.btickets)
                    {
                        if ( m_ticketTimeLeft >= 60 ) {
                            ticketStatusKrb5.Format("Kerb-5 Ticket Life: %02d:%02d",
                                                     (m_ticketTimeLeft / 60L / 60L),
                                                     (m_ticketTimeLeft / 60L % 60L));
                        } else {
                            ticketStatusKrb5.Format("Kerb-5 Ticket Life: < 1 min");
                        }
                    }

                    if (CMainFrame::m_wndStatusBar)
                    {
                        CMainFrame::m_wndStatusBar.SetPaneInfo(1, 111112, SBPS_NORMAL, 130);
                        CMainFrame::m_wndStatusBar.SetPaneText(1, ticketStatusKrb5, SBT_POPOUT);
                    }
                }
            }
            else
            {
                // not installed
                ticketStatusKrb5.Format("Kerb-5: Not Available");

                if (CMainFrame::m_wndStatusBar)
                {
                    CMainFrame::m_wndStatusBar.SetPaneInfo(1, 111112, SBPS_NORMAL, 130);
                    CMainFrame::m_wndStatusBar.SetPaneText(1, ticketStatusKrb5, SBT_POPOUT);
                }
            }
            //KRB5

#ifndef NO_KRB4
            if (CLeashApp::m_hKrb4DLL)
            {
                // KRB4
                UpdateTicketTime(ticketinfo.Krb4);
                if (!ticketinfo.Krb4.btickets)
                {
                    ticketStatusKrb4 = "Kerb-4: No Tickets";
                }
                else if (EXPIRED_TICKETS == ticketinfo.Krb4.btickets)
                {
#ifndef NO_KRB5
                    if (ticketinfo.Krb5.btickets &&
                         EXPIRED_TICKETS != ticketinfo.Krb5.btickets &&
                         m_autoRenewTickets &&
                         !m_autoRenewalAttempted &&
                         ticketinfo.Krb5.renew_till &&
                         (ticketinfo.Krb5.issue_date + ticketinfo.Krb5.renew_till -LeashTime() > 20 * 60) &&
                         pLeash_get_default_use_krb4()
                         )
                    {
                        m_autoRenewalAttempted = 1;
                        ReleaseMutex(ticketinfo.lockObj);
                        AfxBeginThread(RenewTicket,m_hWnd);
                        goto timer_start;
                    }
#endif /* NO_KRB5 */
                    ticketStatusKrb4 = "Kerb-4: Expired Tickets";
                    lowTicketWarningKrb4 = "Your Kerberos Four ticket(s) have expired";
                    if (!m_warningOfTicketTimeLeftLockKrb4)
                        m_warningOfTicketTimeLeftKrb4 = 0;
                    m_warningOfTicketTimeLeftLockKrb4 = ZERO_MINUTES_LEFT;
                    m_ticketTimeLeft = 0;
                }
                else if ( pLeash_get_default_use_krb4() )
                {
                    m_ticketStatusKrb4 = GetLowTicketStatus(4);
                    switch (m_ticketStatusKrb4)
                    {
                    case FIFTEEN_MINUTES_LEFT:
                        ticketinfo.Krb4.btickets = TICKETS_LOW;
                        lowTicketWarningKrb4 = "Less then 15 minutes left on your Kerberos Four ticket(s)";
                        break;
                    case TEN_MINUTES_LEFT:
                        ticketinfo.Krb4.btickets = TICKETS_LOW;
                        lowTicketWarningKrb4 = "Less then 10 minutes left on your Kerberos Four ticket(s)";
                        if (!m_warningOfTicketTimeLeftLockKrb4)
                            m_warningOfTicketTimeLeftKrb4 = 0;
                        m_warningOfTicketTimeLeftLockKrb4 = TEN_MINUTES_LEFT;
                        break;
                    case FIVE_MINUTES_LEFT:
                        ticketinfo.Krb4.btickets = TICKETS_LOW;
                        if (m_warningOfTicketTimeLeftLockKrb4 == TEN_MINUTES_LEFT)
                            m_warningOfTicketTimeLeftKrb4 = 0;
                        m_warningOfTicketTimeLeftLockKrb4 = FIVE_MINUTES_LEFT;
                        lowTicketWarningKrb4 = "Less then 5 minutes left on your Kerberos Four ticket(s)";
                        break;
                    default:
                        m_ticketStatusKrb4 = 0;
                        break;
                    }

                }

                if (CMainFrame::m_isMinimum)
                {
                    // minimized dispay
                    ticketStatusKrb4.Format("Kerb-4: %02d:%02d Left",
                                             (m_ticketTimeLeft / 60L / 60L),
                                             (m_ticketTimeLeft / 60L % 60L));
                }
                else
                {
                    // normal display
                    if (GOOD_TICKETS == ticketinfo.Krb4.btickets ||
                         TICKETS_LOW == ticketinfo.Krb4.btickets)
                    {
                        if ( m_ticketTimeLeft >= 60 ) {
                            ticketStatusKrb4.Format("Kerb-4 Ticket Life: %02d:%02d",
                                                     (m_ticketTimeLeft / 60L / 60L),
                                                     (m_ticketTimeLeft / 60L % 60L));
                        } else {
                            ticketStatusKrb4.Format("Kerb-4 Ticket Life: < 1 min");
                        }
                    }

                    if (CMainFrame::m_wndStatusBar)
                    {
                        CMainFrame::m_wndStatusBar.SetPaneInfo(2, 111111, SBPS_NORMAL, 130);
                        CMainFrame::m_wndStatusBar.SetPaneText(2, ticketStatusKrb4, SBT_POPOUT);
                    }
                }
            }
            else
            {
                ticketStatusKrb4.Format("Kerb-4: Not Available");

                if (CMainFrame::m_wndStatusBar)
                {
                    CMainFrame::m_wndStatusBar.SetPaneInfo(2, 111111, SBPS_NORMAL, 130);
                    CMainFrame::m_wndStatusBar.SetPaneText(2, ticketStatusKrb4, SBT_POPOUT);
                }
            }
            // KRB4
#endif

            if (CLeashApp::m_hAfsDLL)
            {
                // AFS
                UpdateTicketTime(ticketinfo.Afs);
                if (!ticketinfo.Afs.btickets)
                {
                    BOOL AfsEnabled = m_pApp->GetProfileInt("Settings", "AfsStatus", 1);
                    if ( AfsEnabled )
                        ticketStatusAfs = "AFS: No Tickets";
                    else
                        ticketStatusAfs = "AFS: Disabled";
                }
                else if (EXPIRED_TICKETS == ticketinfo.Afs.btickets)
                {
#ifndef NO_KRB5
                    if (ticketinfo.Krb5.btickets &&
                         EXPIRED_TICKETS != ticketinfo.Krb5.btickets &&
                         m_autoRenewTickets &&
                         !m_autoRenewalAttempted &&
                         ticketinfo.Krb5.renew_till &&
                         (ticketinfo.Krb5.issue_date + ticketinfo.Krb5.renew_till -LeashTime() > 20 * 60) &&
                         !stricmp(ticketinfo.Krb5.principal,ticketinfo.Afs.principal)
                         )
                    {
                        m_autoRenewalAttempted = 1;
                        ReleaseMutex(ticketinfo.lockObj);
                        AfxBeginThread(RenewTicket,m_hWnd);
                        goto timer_start;
                    }
#endif /* NO_KRB5 */
                    ticketStatusAfs = "AFS: Expired Tickets";
                    lowTicketWarningAfs = "Your AFS token(s) have expired";
                    if (!m_warningOfTicketTimeLeftLockAfs)
                        m_warningOfTicketTimeLeftAfs = 0;
                    m_warningOfTicketTimeLeftLockAfs = ZERO_MINUTES_LEFT;
                    m_ticketTimeLeft = 0;
                }
                else
                {
                    m_ticketStatusAfs = GetLowTicketStatus(1);
                    switch (m_ticketStatusAfs)
                    {
                    case FIFTEEN_MINUTES_LEFT:
                        ticketinfo.Afs.btickets = TICKETS_LOW;

                        lowTicketWarningAfs = "Less then 15 minutes left on your AFStoken(s)";
                        break;
                    case TEN_MINUTES_LEFT:
                        ticketinfo.Afs.btickets = TICKETS_LOW;

                        lowTicketWarningAfs = "Less then 10 minutes left on your AFS token(s)";

                        if (!m_warningOfTicketTimeLeftLockAfs)
                            m_warningOfTicketTimeLeftAfs = 0;

                        m_warningOfTicketTimeLeftLockAfs = TEN_MINUTES_LEFT;
                        break;
                    case FIVE_MINUTES_LEFT:
                        ticketinfo.Afs.btickets = TICKETS_LOW;
                        if (m_warningOfTicketTimeLeftLockAfs == TEN_MINUTES_LEFT)
                            m_warningOfTicketTimeLeftAfs = 0;

                        m_warningOfTicketTimeLeftLockAfs = FIVE_MINUTES_LEFT;

                        lowTicketWarningAfs = "Less then 5 minutes left on your AFS token(s)";
                        break;
                    default:
                        m_ticketStatusAfs = 0;
                        break;
                    }

                }

                if (CMainFrame::m_isMinimum)
                {
                    // minimized dispay
                    ticketStatusAfs.Format("AFS: %02d:%02d Left",
                                            (m_ticketTimeLeft / 60L / 60L),
                                            (m_ticketTimeLeft / 60L % 60L));
                }
                else
                {
                    // normal display
                    if (GOOD_TICKETS == ticketinfo.Afs.btickets ||
                         TICKETS_LOW == ticketinfo.Afs.btickets)
                    {
                        if ( m_ticketTimeLeft >= 60 ) {
                            ticketStatusAfs.Format("AFS Token Life: %02d:%02d",
                                                    (m_ticketTimeLeft / 60L / 60L),
                                                    (m_ticketTimeLeft / 60L % 60L));
                        } else {
                            ticketStatusAfs.Format("AFS Token Life: < 1 min");
                        }
                    }

                    if (CMainFrame::m_wndStatusBar)
                    {
                        CMainFrame::m_wndStatusBar.SetPaneInfo(3, 111113, SBPS_NORMAL, 130);
                        CMainFrame::m_wndStatusBar.SetPaneText(3, ticketStatusAfs, SBT_POPOUT);
                    }
                }
            }
#ifdef COMMENT
            // we do not set this field because the field does not exist when AfsDLL is NULL
            else
            {
                // not installed
                ticketStatusAfs.Format("AFS: Not Available");

                if (CMainFrame::m_wndStatusBar)
                {
                    CMainFrame::m_wndStatusBar.SetPaneInfo(3, 111113, SBPS_NORMAL, 130);
                    CMainFrame::m_wndStatusBar.SetPaneText(3, ticketStatusAfs, SBT_POPOUT);
                }
            }
#endif /* COMMENT */
            // AFS

#ifndef NO_KRB5
            if ( m_ticketStatusKrb5 == TWENTY_MINUTES_LEFT &&
                 m_autoRenewTickets && !m_autoRenewalAttempted && ticketinfo.Krb5.renew_till &&
                 (ticketinfo.Krb5.issue_date + ticketinfo.Krb5.renew_till - LeashTime() > 20 * 60))
            {
                m_autoRenewalAttempted = 1;
                ReleaseMutex(ticketinfo.lockObj);
                AfxBeginThread(RenewTicket,m_hWnd);
                goto timer_start;
            }
#endif /* NO_KRB5 */

            BOOL warningKrb5 = m_ticketStatusKrb5 > NO_TICKETS &&
                m_ticketStatusKrb5 < TWENTY_MINUTES_LEFT &&
                    !m_warningOfTicketTimeLeftKrb5;
            BOOL warningKrb4 = m_ticketStatusKrb4 > NO_TICKETS &&
                m_ticketStatusKrb4 < TWENTY_MINUTES_LEFT &&
                    !m_warningOfTicketTimeLeftKrb4;
            BOOL warningAfs = m_ticketStatusAfs > NO_TICKETS &&
                m_ticketStatusAfs < TWENTY_MINUTES_LEFT &&
                    !m_warningOfTicketTimeLeftAfs;

            // Play warning message only once per each case statement above
            if (warningKrb4 || warningKrb5 || warningAfs)
            {

                CString lowTicketWarning = "";
                int warnings = 0;

                if (warningKrb5) {
                    lowTicketWarning += lowTicketWarningKrb5;
                    m_warningOfTicketTimeLeftKrb5 = ON;
                    warnings++;
                }
                if (warningKrb4) {
                    if ( warnings )
                        lowTicketWarning += "\n";
                    lowTicketWarning += lowTicketWarningKrb4;
                    m_warningOfTicketTimeLeftKrb4 = ON;
                    warnings++;
                }
                if (warningAfs) {
                    if ( warnings )
                        lowTicketWarning += "\n";
                    lowTicketWarning += lowTicketWarningAfs;
                    m_warningOfTicketTimeLeftAfs = ON;
                    warnings++;
                }

                ReleaseMutex(ticketinfo.lockObj);
                AlarmBeep();
                PostWarningMessage(lowTicketWarning);
                if (WaitForSingleObject( ticketinfo.lockObj, 100 ) != WAIT_OBJECT_0)
                    throw("Unable to lock ticketinfo");
            }

            CTime tTimeDate = CTime::GetCurrentTime();

            if (CMainFrame::m_isMinimum)
            {
                if ( CLeashApp::m_hAfsDLL )
                    strTimeDate = ( "Leash - "
                                    "[" + ticketStatusKrb5 + "] - " +
                                    "[" + ticketStatusKrb4 + "] - " +
                                    "[" + ticketStatusAfs + "] - " +
                                    "[" + ticketinfo.Krb5.principal + "]" + " - " +
                                    tTimeDate.Format("%A, %B %d, %Y  %H:%M "));
                else
                    strTimeDate = ( "Leash - "
                                    "[" + ticketStatusKrb5 + "] - " +
                                    "[" + ticketStatusKrb4 + "] - " +
                                    "[" + ticketinfo.Krb5.principal + "]" + " - " +
                                    tTimeDate.Format("%A, %B %d, %Y  %H:%M "));
            }
            else
            {
                strTimeDate = ("Leash - " +
                                tTimeDate.Format("%A, %B %d, %Y  %H:%M ")
                                //timeDate.Format("%d %b %y %H:%M:%S - ")
                                );
            }
            ::SetWindowText(CLeashApp::m_hProgram, strTimeDate);

            if (CLeashApp::m_hKrb5DLL) {
                if ( ticketinfo.Krb5.btickets )
                    strTimeDate = ( "Leash: "
                                    "[" + ticketStatusKrb5 + "]" +
                                    " - [" + ticketinfo.Krb5.principal + "]");
                else
                    strTimeDate = "Leash: Kerb-5 No Tickets";
            } else {
                if ( ticketinfo.Krb4.btickets )
                    strTimeDate = ( "Leash: "
                                    "[" + ticketStatusKrb4 + "]" +
                                    " - [" + ticketinfo.Krb4.principal + "]");
                else
                    strTimeDate = "Leash: Kerb-4 No Tickets";
            }
            ReleaseMutex(ticketinfo.lockObj);

            SetTrayText(NIM_MODIFY, strTimeDate);

            m_updateDisplayCount++;
            m_alreadyPlayedDisplayCount++;
        }
        } catch (...) {
        }
        InterlockedIncrement(&m_timerMsgNotInProgress);
    }  // WM_TIMER


    if (UPDATE_DISPLAY_TIME == m_updateDisplayCount)
    {
        m_updateDisplayCount = 0;
        SendMessage(WM_COMMAND, ID_UPDATE_DISPLAY, 0);
    }

    if (m_alreadyPlayedDisplayCount > 2)
    {
        m_alreadyPlayedDisplayCount = 0;
        m_alreadyPlayed = FALSE;
    }

    if (CMainFrame::m_isBeingResized)
    {
        m_startup = FALSE;

        UpdateWindow();

        CMainFrame::m_isBeingResized = FALSE;
    }

	if (::IsWindow(pMsg->hwnd))
		return CListView::PreTranslateMessage(pMsg);
	else
		return FALSE;
}

VOID CLeashView::OnLowTicketAlarm()
{
    m_lowTicketAlarm = !m_lowTicketAlarm;

    if (m_pApp)
        m_pApp->WriteProfileInt("Settings", "LowTicketAlarm", m_lowTicketAlarm);
}

VOID CLeashView::OnUpdateLowTicketAlarm(CCmdUI* pCmdUI)
{
    pCmdUI->SetCheck(m_lowTicketAlarm);
}

VOID CLeashView::OnAutoRenew()
{
    m_autoRenewTickets = !m_autoRenewTickets;

    if (m_pApp)
        m_pApp->WriteProfileInt("Settings", "AutoRenewTickets", m_autoRenewTickets);

    m_autoRenewalAttempted = 0;
}

VOID CLeashView::OnUpdateAutoRenew(CCmdUI* pCmdUI)
{
    pCmdUI->SetCheck(m_autoRenewTickets);
}

VOID CLeashView::AlarmBeep()
{
	if (m_lowTicketAlarmSound)
	{
		::Beep(2000, 200);
		::Beep(200, 200);
		::Beep(700, 200);
	}
}

VOID CLeashView::OnUpdateProperties(CCmdUI* pCmdUI)
{
    if (CLeashApp::m_hKrb5DLL
#ifndef NO_KRB4
	|| CLeashApp::m_hKrb4DLL
#endif
	)
        pCmdUI->Enable();
    else
        pCmdUI->Enable(FALSE);
}

VOID CLeashView::OnUpdateKrb4Properties(CCmdUI* pCmdUI)
{
#ifndef NO_KRB4
    if (CLeashApp::m_hKrb4DLL)
        pCmdUI->Enable();
    else
#endif
        pCmdUI->Enable(FALSE);
}

VOID CLeashView::OnUpdateKrb5Properties(CCmdUI* pCmdUI)
{
    if (CLeashApp::m_hKrb5DLL)
        pCmdUI->Enable();
    else
        pCmdUI->Enable(FALSE);
}

VOID CLeashView::OnUpdateAfsControlPanel(CCmdUI* pCmdUI)
{
////Is the comment even correct?
#ifndef NO_KRB4
    // need Krb 4 to get AFS tokens
    if (CLeashApp::m_hAfsDLL && CLeashApp::m_hKrb4DLL)
        pCmdUI->Enable();
    else
#endif
        pCmdUI->m_pMenu->DeleteMenu(pCmdUI->m_nID, MF_BYCOMMAND);
}

void CLeashView::OnHelpLeash32()
{
#ifdef CALL_HTMLHELP
	AfxGetApp()->HtmlHelp(HID_LEASH_PROGRAM);
#else
    AfxGetApp()->WinHelp(HID_LEASH_PROGRAM);
#endif
}

void CLeashView::OnHelpKerberos()
{
#ifdef CALL_HTMLHELP
    AfxGetApp()->HtmlHelp(HID_ABOUT_KERBEROS);
#else
    AfxGetApp()->WinHelp(HID_ABOUT_KERBEROS);
#endif
}

void CLeashView::OnHelpWhyuseleash32()
{
#ifdef CALL_HTMLHELP
    AfxGetApp()->HtmlHelp(HID_WHY_USE_LEASH32);
#else
    AfxGetApp()->WinHelp(HID_WHY_USE_LEASH32);
#endif
}

void CLeashView::OnSysColorChange()
{
    change_icon_size = FALSE;
    CWnd::OnSysColorChange();
    OnLargeIcons();
    m_imageList.SetBkColor(GetSysColor(COLOR_WINDOW));
    change_icon_size = TRUE;
}


LRESULT
CLeashView::OnObtainTGTWithParam(WPARAM wParam, LPARAM lParam)
{
    LRESULT res = 0;
    char * param = (char *) GlobalLock((HGLOBAL) lParam);
    LSH_DLGINFO_EX ldi;
    ldi.size = sizeof(ldi);
    ldi.dlgtype = DLGTYPE_PASSWD;
    ldi.use_defaults = 1;
    ldi.title = ldi.in.title;
    ldi.username = ldi.in.username;
    ldi.realm = ldi.in.realm;
    if ( param ) {
        if ( *param )
            strcpy(ldi.in.title,param);
        param += strlen(param) + 1;
        if ( *param )
            strcpy(ldi.in.username,param);
        param += strlen(param) + 1;
        if ( *param )
            strcpy(ldi.in.realm,param);
        param += strlen(param) + 1;
	if ( *param )
	    strcpy(ldi.in.ccache,param);
    } else {
        strcpy(ldi.in.title,"Get Ticket");
    }

    res = pLeash_kinit_dlg_ex(m_hWnd, &ldi);
    GlobalUnlock((HGLOBAL) lParam);
    ::SendMessage(m_hWnd, WM_COMMAND, ID_UPDATE_DISPLAY, 0);
    return res;
}
