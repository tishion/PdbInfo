#include "stdafx.h"
#include "AboutDlg.h"
#include "MainDlg.h"
#include "PEHelper.h"

class CProcessDlg : 
	public CDialogImpl<CProcessDlg>
{
public:
	enum { IDD = IDD_DIALOG_PROCESS };

	BEGIN_MSG_MAP(CProcessDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		COMMAND_ID_HANDLER(IDCANCEL, OnCloseCmd)
		COMMAND_HANDLER(IDC_BTN_CANCEL, BN_CLICKED, OnBnClickedBtnCancel)
	END_MSG_MAP()

	// Handler prototypes (uncomment arguments if needed):
	//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	void SetParent(CMainDlg* pParent)
	{
		m_pMainDlg = pParent;
	}

	void SetDropHandle(HDROP h)
	{
		m_hDrop = h;
	}

	void StepProgressBar()
	{
		m_ProgressBar.StepIt();
	}

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		CenterWindow(GetParent());
		m_ProgressBar.Attach(GetDlgItem(IDC_PROGRESS));
		m_Button.Attach(GetDlgItem(IDC_BTN_CANCEL));

		ATLASSERT(NULL != m_pMainDlg);
		ATLASSERT(NULL != m_hDrop);

		UINT nCount = ::DragQueryFile(m_hDrop, -1, NULL, 0);
		m_ProgressBar.SetRange(0, nCount);
		m_ProgressBar.SetStep(1);
		m_ProgressBar.SetPos(0);

		m_bCancel = FALSE;

		m_hThread = ::CreateThread(NULL, 0, ProcessFiles, (LPVOID)this, 0, &m_dwTid);
		return TRUE;
	}

	LRESULT OnCloseCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		EndDialog(wID);
		return 0;
	}

	LRESULT OnBnClickedBtnCancel(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		// TODO: Add your control notification handler code here
		m_bCancel = TRUE;
		return 0;
	}

	static DWORD CALLBACK ProcessFiles(LPVOID pVoid)
	{
		CProcessDlg* pThis = (CProcessDlg*)pVoid;

		if (NULL == pThis ||
			NULL == pThis->m_pMainDlg ||
			NULL == pThis->m_hDrop)
		{
			return 0;
		}

		HDROP hDrop = pThis->m_hDrop;
		CMainDlg* pMainDlg = pThis->m_pMainDlg;

		CString strResult;

		UINT nCount = ::DragQueryFile(hDrop, -1, NULL, 0);

		for (UINT i=0; i<nCount && !(pThis->m_bCancel); i++)
		{
			CString strFilePath;

			UINT cchBuffer = ::DragQueryFile(hDrop, i, NULL, 0) + 1;
			::DragQueryFile(hDrop, i, strFilePath.GetBuffer(cchBuffer), cchBuffer);
			strFilePath.ReleaseBuffer();

			CPEHelper peHelper;
			if (peHelper.OpenAndVerify(strFilePath.GetString()))
			{
				CString strBinFileIndex;
				CString strPdbFileName;
				CString strPdbFileIndex;

				peHelper.GetBinFileIndex(strBinFileIndex);
				peHelper.GetPdbFileIndex(strPdbFileIndex, strPdbFileName);

				if (strBinFileIndex.IsEmpty())
				{
					strBinFileIndex = _T("Unknown");
				}

				if (strPdbFileName.IsEmpty())
				{
					strPdbFileName = _T("Unknown");
				}

				if (strPdbFileIndex.IsEmpty())
				{
					strPdbFileIndex = _T("Unknown");
				}

				CString strItem;
				strItem.Format(
					_T("%s\r\n")
					_T("\tPdbFileName:  %s\r\n")
					_T("\tBinFileIndex: %s\r\n")
					_T("\tPdbFileIndex: %s\r\n"),
					strFilePath,
					strPdbFileName,
					strBinFileIndex,
					strPdbFileIndex);

				strResult.Append(strItem);
				strResult.Append(_T("\r\n"));
			}
			else
			{
				CString strItem;
				strItem.Format(
					_T("%s\r\n")
					_T("\tNot PE file!\r\n"),
					strFilePath);

				strResult.Append(strItem);
				strResult.Append(_T("\r\n"));
			}

			pThis->StepProgressBar();
		}

		pMainDlg->SetInfoText(strResult);

		pThis->PostMessage(WM_CLOSE);
		
		return 0;
	}

public:
	CMainDlg*			m_pMainDlg;
	HDROP				m_hDrop;
	BOOL				m_bCancel;
private:
	DWORD				m_dwTid;
	HANDLE				m_hThread;

	CProgressBarCtrl	m_ProgressBar;
	CButton				m_Button;
};


BOOL CMainDlg::PreTranslateMessage(MSG* pMsg)
{
	if (pMsg->message == WM_KEYDOWN)
	{
		UINT  nKeyCode = pMsg->wParam;

		if ((nKeyCode == _T('C') || 
			nKeyCode == _T('X') || 
			nKeyCode == _T('V')) && 
			(::GetKeyState(VK_CONTROL) & 0x8000))
		{
			::TranslateMessage(pMsg);
			::DispatchMessage(pMsg);
			return(TRUE);
		}

		if (nKeyCode == _T('A') && 
			(::GetKeyState(VK_CONTROL) & 0x8000))
		{
			m_editInfor.SetSel(0, -1);
			return TRUE;
		}
	}

	return CWindow::IsDialogMessage(pMsg);
}

LRESULT CMainDlg::OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
	// center the dialog on the screen
	CenterWindow();

	DragAcceptFiles(TRUE);

	m_editInfor.Attach(GetDlgItem(IDC_EDIT_INFO));
	// set icons
	HICON hIcon = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON));
	SetIcon(hIcon, TRUE);
	HICON hIconSmall = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON));
	SetIcon(hIconSmall, FALSE);

	// register object for message filtering and idle updates
	CMessageLoop* pLoop = _Module.GetMessageLoop();
	ATLASSERT(pLoop != NULL);
	pLoop->AddMessageFilter(this);
	pLoop->AddIdleHandler(this);

	return TRUE;
}

LRESULT CMainDlg::OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
	// unregister message filtering and idle updates
	CMessageLoop* pLoop = _Module.GetMessageLoop();
	ATLASSERT(pLoop != NULL);
	pLoop->RemoveMessageFilter(this);
	pLoop->RemoveIdleHandler(this);

	return 0;
}

LRESULT CMainDlg::OnCancel(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	CloseDialog(wID);
	return 0;
}

void CMainDlg::CloseDialog(int nVal)
{
	DestroyWindow();
	::PostQuitMessage(nVal);
}

LRESULT CMainDlg::OnSize(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
	// TODO: Add your message handler code here and/or call default
	CRect rcClient;
	GetClientRect(&rcClient);

	m_editInfor.MoveWindow(rcClient);

	return 0;
}

LRESULT CMainDlg::OnDropFiles(UINT /*uMsg*/, WPARAM wParam, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
	HDROP hDrop = (HDROP)wParam;

	if (NULL != hDrop)
	{
		CProcessDlg dlg;
		dlg.SetParent(this);
		dlg.SetDropHandle(hDrop);
		dlg.DoModal(m_hWnd);
		::DragFinish(hDrop);
	}

	return 0;
}

void CMainDlg::SetInfoText(CString strInfo)
{
	m_editInfor.Clear();
	m_editInfor.SetWindowText(strInfo);
}
