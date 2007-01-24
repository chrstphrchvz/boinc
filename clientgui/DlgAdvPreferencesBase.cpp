///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Oct 13 2006)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif //__BORLANDC__

#ifndef WX_PRECOMP
#include <wx/wx.h>
#endif //WX_PRECOMP

#include "DlgAdvPreferencesBase.h"

///////////////////////////////////////////////////////////////////////////

CDlgAdvPreferencesBase::CDlgAdvPreferencesBase( wxWindow* parent, int id, wxString title, wxPoint pos, wxSize size, int style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetExtraStyle( wxWS_EX_VALIDATE_RECURSIVELY );
	this->Centre( wxBOTH );
	
	wxBoxSizer* bSizer1;
	bSizer1 = new wxBoxSizer( wxVERTICAL );
	
	wxStaticBoxSizer* sbSizer92;
	sbSizer92 = new wxStaticBoxSizer( new wxStaticBox( this, -1, wxT("") ), wxHORIZONTAL );
	
	m_bmpWarning = new wxStaticBitmap( this, ID_DEFAULT, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	m_bmpWarning->SetMinSize( wxSize( 48,48 ) );
	
	sbSizer92->Add( m_bmpWarning, 0, wxALIGN_CENTER_VERTICAL|wxALL, 0 );
	
	m_staticText321 = new wxStaticText( this, ID_DEFAULT, _("This dialog controls preferences on this computer only.\nOn Save - preferences will be stored locally.\nIf you would like to revert to web-based settings, click the Clear-Button."), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer92->Add( m_staticText321, 1, wxALL, 1 );
	
	m_btnClear = new wxButton( this, ID_BTN_CLEAR, _("Clear"), wxDefaultPosition, wxDefaultSize, 0 );
	m_btnClear->SetToolTip( wxT("clears all local preferences and close the dialog") );
	
	sbSizer92->Add( m_btnClear, 0, wxALIGN_BOTTOM|wxALL, 1 );
	
	bSizer1->Add( sbSizer92, 0, wxALL|wxEXPAND, 1 );
	
	m_panelControls = new wxPanel( this, ID_DEFAULT, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	m_panelControls->SetExtraStyle( wxWS_EX_VALIDATE_RECURSIVELY );
	
	wxBoxSizer* bSizer3;
	bSizer3 = new wxBoxSizer( wxVERTICAL );
	
	m_Notebook = new wxNotebook( m_panelControls, ID_DEFAULT, wxDefaultPosition, wxDefaultSize, wxNB_FLAT|wxNB_TOP );
	m_Notebook->SetExtraStyle( wxWS_EX_VALIDATE_RECURSIVELY );
	
	m_panelProcessor = new wxPanel( m_Notebook, ID_TABPAGE_PROC, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	m_panelProcessor->SetExtraStyle( wxWS_EX_VALIDATE_RECURSIVELY );
	
	wxBoxSizer* bSizer7;
	bSizer7 = new wxBoxSizer( wxVERTICAL );
	
	wxStaticBoxSizer* sbSizer4;
	sbSizer4 = new wxStaticBoxSizer( new wxStaticBox( m_panelProcessor, -1, _("when do work") ), wxVERTICAL );
	
	m_chkProcOnBatteries = new wxCheckBox( m_panelProcessor, ID_CHKPROCONBATTERIES, _("while computer is on batteries"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkProcOnBatteries->SetToolTip( wxT("check this, if you want that this host does work while it runs on batteries") );
	
	sbSizer4->Add( m_chkProcOnBatteries, 0, wxALL, 5 );
	
	m_chkProcInUse = new wxCheckBox( m_panelProcessor, ID_CHKPROCINUSE, _("while computer is in use"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkProcInUse->SetToolTip( wxT("check this, if work should be done while you are working at this host") );
	
	sbSizer4->Add( m_chkProcInUse, 0, wxALL, 5 );
	
	wxFlexGridSizer* fgSizer5;
	fgSizer5 = new wxFlexGridSizer( 2, 4, 0, 0 );
	fgSizer5->AddGrowableCol( 3 );
	fgSizer5->SetFlexibleDirection( wxHORIZONTAL );
	fgSizer5->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText26 = new wxStaticText( m_panelProcessor, ID_DEFAULT, _("only if computer is idle for"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer5->Add( m_staticText26, 0, wxALL, 5 );
	
	m_txtProcIdleFor = new wxTextCtrl( m_panelProcessor, ID_TXTPROCIDLEFOR, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	m_txtProcIdleFor->SetToolTip( wxT("work is done after this amount of minutes idle time (no mouse movement and/or keyboard input)") );
	
	fgSizer5->Add( m_txtProcIdleFor, 0, wxALL, 1 );
	
	m_staticText27 = new wxStaticText( m_panelProcessor, ID_DEFAULT, _("minutes"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer5->Add( m_staticText27, 0, wxALL, 5 );
	
	m_staticText28 = new wxStaticText( m_panelProcessor, ID_DEFAULT, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer5->Add( m_staticText28, 0, wxALL, 5 );
	
	sbSizer4->Add( fgSizer5, 0, wxEXPAND, 5 );
	
	bSizer7->Add( sbSizer4, 0, wxEXPAND, 5 );
	
	wxStaticBoxSizer* sbSizer91;
	sbSizer91 = new wxStaticBoxSizer( new wxStaticBox( m_panelProcessor, -1, _("work time restrictions") ), wxVERTICAL );
	
	wxBoxSizer* bSizer111;
	bSizer111 = new wxBoxSizer( wxHORIZONTAL );
	
	m_rbtProcEveryDay = new wxRadioButton( m_panelProcessor, ID_RBTPROCEVERYDAY, _("every day between hours of"), wxDefaultPosition, wxDefaultSize, wxRB_GROUP);
	m_rbtProcEveryDay->SetToolTip( wxT("sets worktime restrictions for every day of the week\n(no restrictions if values are equal)") );
	
	bSizer111->Add( m_rbtProcEveryDay, 0, wxALL, 5 );
	
	m_txtProcEveryDayStart = new wxTextCtrl( m_panelProcessor, ID_TXTPROCEVERYDAYSTART, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	m_txtProcEveryDayStart->SetToolTip( wxT("start work at this time") );
	
	bSizer111->Add( m_txtProcEveryDayStart, 0, wxALL, 1 );
	
	m_staticText25 = new wxStaticText( m_panelProcessor, ID_DEFAULT, _("and"), wxDefaultPosition, wxDefaultSize, wxALIGN_CENTRE );
	bSizer111->Add( m_staticText25, 0, wxALL|wxEXPAND, 5 );
	
	m_txtProcEveryDayStop = new wxTextCtrl( m_panelProcessor, ID_TXTPROCEVERYDAYSTOP, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	m_txtProcEveryDayStop->SetToolTip( wxT("stop work at this time") );
	
	bSizer111->Add( m_txtProcEveryDayStop, 0, wxALL, 1 );
	
	sbSizer91->Add( bSizer111, 0, wxEXPAND, 1 );
	
	m_rbtProcSpecialTimes = new wxRadioButton( m_panelProcessor, ID_RBTPROCSPECIALTIMES, _("as specified here:"), wxDefaultPosition, wxDefaultSize, 0);
	m_rbtProcSpecialTimes->SetToolTip( wxT("set special work time restrictions for checked days") );
	
	sbSizer91->Add( m_rbtProcSpecialTimes, 0, wxALL, 5 );
	
	m_panelProcSpecialTimes = new wxPanel( m_panelProcessor, ID_DEFAULT, wxDefaultPosition, wxDefaultSize, wxSUNKEN_BORDER|wxTAB_TRAVERSAL );
	m_panelProcSpecialTimes->SetExtraStyle( wxWS_EX_VALIDATE_RECURSIVELY );
	
	wxBoxSizer* bSizer11;
	bSizer11 = new wxBoxSizer( wxVERTICAL );
	
	wxFlexGridSizer* fgSizer6;
	fgSizer6 = new wxFlexGridSizer( 4, 4, 0, 0 );
	fgSizer6->SetFlexibleDirection( wxHORIZONTAL );
	fgSizer6->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_chkProcMonday = new wxCheckBox( m_panelProcSpecialTimes, ID_CHKPROCMONDAY, _("Monday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkProcMonday->SetToolTip( wxT("check this, if you want that work is done on monday") );
	
	fgSizer6->Add( m_chkProcMonday, 0, wxALL, 5 );
	
	m_txtProcMonday = new wxTextCtrl( m_panelProcSpecialTimes, ID_TXTPROCMONDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer6->Add( m_txtProcMonday, 0, wxALL, 1 );
	
	m_chkProcTuesday = new wxCheckBox( m_panelProcSpecialTimes, ID_CHKPROCTUESDAY, _("Tuesday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkProcTuesday->SetToolTip( wxT("check this, if you want that work is done on tuesday") );
	
	fgSizer6->Add( m_chkProcTuesday, 0, wxALL, 5 );
	
	m_txtProcTuesday = new wxTextCtrl( m_panelProcSpecialTimes, ID_TXTPROCTUESDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer6->Add( m_txtProcTuesday, 0, wxALL, 1 );
	
	m_chkProcWednesday = new wxCheckBox( m_panelProcSpecialTimes, ID_CHKPROCWEDNESDAY, _("Wednesday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkProcWednesday->SetToolTip( wxT("check this, if you want that work is done on wednesday") );
	
	fgSizer6->Add( m_chkProcWednesday, 0, wxALL, 5 );
	
	m_txtProcWednesday = new wxTextCtrl( m_panelProcSpecialTimes, ID_TXTPROCWEDNESDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer6->Add( m_txtProcWednesday, 0, wxALL, 1 );
	
	m_chkProcThursday = new wxCheckBox( m_panelProcSpecialTimes, ID_CHKPROCTHURSDAY, _("Thursday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkProcThursday->SetToolTip( wxT("check this, if you want that work is done on thursday") );
	
	fgSizer6->Add( m_chkProcThursday, 0, wxALL, 5 );
	
	m_txtProcThursday = new wxTextCtrl( m_panelProcSpecialTimes, ID_TXTPROCTHURSDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer6->Add( m_txtProcThursday, 0, wxALL, 1 );
	
	m_chkProcFriday = new wxCheckBox( m_panelProcSpecialTimes, ID_CHKPROCFRIDAY, _("Friday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkProcFriday->SetToolTip( wxT("check this, if you want that work is done on friday") );
	
	fgSizer6->Add( m_chkProcFriday, 0, wxALL, 5 );
	
	m_txtProcFriday = new wxTextCtrl( m_panelProcSpecialTimes, ID_TXTPROCFRIDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer6->Add( m_txtProcFriday, 0, wxALL, 1 );
	
	m_chkProcSaturday = new wxCheckBox( m_panelProcSpecialTimes, ID_CHKPROCSATURDAY, _("Saturday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkProcSaturday->SetToolTip( wxT("check this, if you want that work is done on saturday") );
	
	fgSizer6->Add( m_chkProcSaturday, 0, wxALL, 5 );
	
	m_txtProcSaturday = new wxTextCtrl( m_panelProcSpecialTimes, ID_TXTPROCSATURDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer6->Add( m_txtProcSaturday, 0, wxALL, 1 );
	
	m_chkProcSunday = new wxCheckBox( m_panelProcSpecialTimes, ID_CHKPROCSUNDAY, _("Sunday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkProcSunday->SetToolTip( wxT("check this, if you want that work is done on sunday") );
	
	fgSizer6->Add( m_chkProcSunday, 0, wxALL, 5 );
	
	m_txtProcSunday = new wxTextCtrl( m_panelProcSpecialTimes, ID_TXTPROCSUNDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer6->Add( m_txtProcSunday, 0, wxALL, 1 );
	
	bSizer11->Add( fgSizer6, 1, wxEXPAND, 1 );
	
	m_panelProcSpecialTimes->SetSizer( bSizer11 );
	m_panelProcSpecialTimes->Layout();
	bSizer11->Fit( m_panelProcSpecialTimes );
	sbSizer91->Add( m_panelProcSpecialTimes, 1, wxEXPAND | wxALL, 1 );
	
	bSizer7->Add( sbSizer91, 0, wxEXPAND, 1 );
	
	wxStaticBoxSizer* sbSizer3;
	sbSizer3 = new wxStaticBoxSizer( new wxStaticBox( m_panelProcessor, -1, _("other options") ), wxVERTICAL );
	
	wxFlexGridSizer* fgSizer3;
	fgSizer3 = new wxFlexGridSizer( 3, 3, 0, 0 );
	fgSizer3->AddGrowableCol( 2 );
	fgSizer3->SetFlexibleDirection( wxHORIZONTAL );
	fgSizer3->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText18 = new wxStaticText( m_panelProcessor, ID_DEFAULT, _("switch between applications between every"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	fgSizer3->Add( m_staticText18, 0, wxALL|wxEXPAND, 5 );
	
	m_txtProcSwitchEvery = new wxTextCtrl( m_panelProcessor, ID_TXTPROCSWITCHEVERY, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	fgSizer3->Add( m_txtProcSwitchEvery, 0, wxALL, 1 );
	
	m_staticText19 = new wxStaticText( m_panelProcessor, ID_DEFAULT, _("minutes"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer3->Add( m_staticText19, 0, wxALL, 5 );
	
	m_staticText20 = new wxStaticText( m_panelProcessor, ID_DEFAULT, _("on multiprocessor systems, use at most"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	fgSizer3->Add( m_staticText20, 0, wxALL|wxEXPAND, 5 );
	
	m_txtProcUseProcessors = new wxTextCtrl( m_panelProcessor, ID_TXTPROCUSEPROCESSORS, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	fgSizer3->Add( m_txtProcUseProcessors, 0, wxALL, 1 );
	
	m_staticText21 = new wxStaticText( m_panelProcessor, ID_DEFAULT, _("processors"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer3->Add( m_staticText21, 0, wxALL, 5 );
	
	m_staticText22 = new wxStaticText( m_panelProcessor, ID_DEFAULT, _("use at most"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	fgSizer3->Add( m_staticText22, 0, wxALL|wxEXPAND, 5 );
	
	m_txtProcUseCPUTime = new wxTextCtrl( m_panelProcessor, ID_TXTPOCUSECPUTIME, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	fgSizer3->Add( m_txtProcUseCPUTime, 0, wxALL, 1 );
	
	m_staticText23 = new wxStaticText( m_panelProcessor, ID_DEFAULT, _("% CPU time"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer3->Add( m_staticText23, 0, wxALL, 5 );
	
	sbSizer3->Add( fgSizer3, 0, wxEXPAND, 1 );
	
	bSizer7->Add( sbSizer3, 0, wxEXPAND, 1 );
	
	m_panelProcessor->SetSizer( bSizer7 );
	m_panelProcessor->Layout();
	bSizer7->Fit( m_panelProcessor );
	m_Notebook->AddPage( m_panelProcessor, _("processor usage"), true );
	m_panelNetwork = new wxPanel( m_Notebook, ID_TABPAGE_NET, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	m_panelNetwork->SetExtraStyle( wxWS_EX_VALIDATE_RECURSIVELY );
	
	wxBoxSizer* bSizer12;
	bSizer12 = new wxBoxSizer( wxVERTICAL );
	
	wxStaticBoxSizer* sbSizer8;
	sbSizer8 = new wxStaticBoxSizer( new wxStaticBox( m_panelNetwork, -1, _("general options") ), wxVERTICAL );
	
	wxFlexGridSizer* fgSizer7;
	fgSizer7 = new wxFlexGridSizer( 3, 3, 0, 0 );
	fgSizer7->AddGrowableCol( 2 );
	fgSizer7->SetFlexibleDirection( wxHORIZONTAL );
	fgSizer7->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText30 = new wxStaticText( m_panelNetwork, ID_DEFAULT, _("connect about every"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer7->Add( m_staticText30, 0, wxALL, 5 );
	
	m_txtNetConnectInterval = new wxTextCtrl( m_panelNetwork, ID_TXTNETCONNECTINTERVAL, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	m_txtNetConnectInterval->SetToolTip( wxT("specify the connect-to-server frequency\n(this influences the amount of work is requested from projects)") );
	
	fgSizer7->Add( m_txtNetConnectInterval, 0, wxALL, 1 );
	
	m_staticText31 = new wxStaticText( m_panelNetwork, ID_DEFAULT, _("days"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer7->Add( m_staticText31, 0, wxALL, 5 );
	
	m_staticText32 = new wxStaticText( m_panelNetwork, ID_DEFAULT, _("maximum download rate"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer7->Add( m_staticText32, 0, wxALL, 5 );
	
	m_txtNetDownloadRate = new wxTextCtrl( m_panelNetwork, ID_TXTNETDOWNLOADRATE, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	fgSizer7->Add( m_txtNetDownloadRate, 0, wxALL, 1 );
	
	m_staticText33 = new wxStaticText( m_panelNetwork, ID_DEFAULT, _("KBytes/second"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer7->Add( m_staticText33, 0, wxALL, 5 );
	
	m_staticText34 = new wxStaticText( m_panelNetwork, ID_DEFAULT, _("maximum upload rate"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer7->Add( m_staticText34, 0, wxALL, 5 );
	
	m_txtNetUploadRate = new wxTextCtrl( m_panelNetwork, ID_TXTNETUPLOADRATE, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	fgSizer7->Add( m_txtNetUploadRate, 0, wxALL, 1 );
	
	m_staticText35 = new wxStaticText( m_panelNetwork, ID_DEFAULT, _("KBytes/second"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer7->Add( m_staticText35, 0, wxALL, 5 );
	
	m_chkNetSkipImageVerification = new wxCheckBox( m_panelNetwork, ID_CHKNETSKIPIMAGEVERIFICATION, _("skip image file verification"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkNetSkipImageVerification->SetToolTip( wxT("check this only if your internet provider modifies image files") );
	
	fgSizer7->Add( m_chkNetSkipImageVerification, 0, wxALL, 5 );
	
	sbSizer8->Add( fgSizer7, 0, wxEXPAND, 1 );
	
	bSizer12->Add( sbSizer8, 0, wxEXPAND, 1 );
	
	wxStaticBoxSizer* sbSizer7;
	sbSizer7 = new wxStaticBoxSizer( new wxStaticBox( m_panelNetwork, -1, _("connect options") ), wxVERTICAL );
	
	m_chkNetConfirmBeforeConnect = new wxCheckBox( m_panelNetwork, ID_CHKNETCONFIRMBEFORECONNECT, _("confirm before connecting to internet"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkNetConfirmBeforeConnect->SetToolTip( wxT("if checked, a confirmation dialog is displayed before trying to connect to the internet") );
	
	sbSizer7->Add( m_chkNetConfirmBeforeConnect, 0, wxALL, 5 );
	
	m_chkNetDisconnectWhenDone = new wxCheckBox( m_panelNetwork, ID_CHKNETDISCONNECTWHENDONE, _("disconnect when done"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkNetDisconnectWhenDone->SetToolTip( wxT("if checked, BOINC hangs up when netwrok transfer is done\n(only relevant for dialup-connection)") );
	
	sbSizer7->Add( m_chkNetDisconnectWhenDone, 0, wxALL, 5 );
	
	bSizer12->Add( sbSizer7, 0, wxEXPAND, 1 );
	
	wxStaticBoxSizer* sbSizer9;
	sbSizer9 = new wxStaticBoxSizer( new wxStaticBox( m_panelNetwork, -1, _("usage restrictions") ), wxVERTICAL );
	
	wxBoxSizer* bSizer14;
	bSizer14 = new wxBoxSizer( wxHORIZONTAL );
	
	m_rbtNetEveryDay = new wxRadioButton( m_panelNetwork, ID_RBTNETEVERYDAY, _("use network only between the hours of"), wxDefaultPosition, wxDefaultSize, wxRB_GROUP);
	m_rbtNetEveryDay->SetToolTip( wxT("sets network usage restriction for every day of the week") );
	
	bSizer14->Add( m_rbtNetEveryDay, 0, wxALL, 5 );
	
	m_txtNetEveryDayStart = new wxTextCtrl( m_panelNetwork, ID_TXTNETEVERYDAYSTART, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), 0 );
	m_txtNetEveryDayStart->SetToolTip( wxT("network usage start hour") );
	
	bSizer14->Add( m_txtNetEveryDayStart, 0, wxALL, 1 );
	
	m_staticText37 = new wxStaticText( m_panelNetwork, ID_DEFAULT, _("and"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer14->Add( m_staticText37, 0, wxALL, 5 );
	
	m_txtNetEveryDayStop = new wxTextCtrl( m_panelNetwork, ID_TXTNETEVERYDAYSTOP, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), 0 );
	m_txtNetEveryDayStop->SetToolTip( wxT("network usage stop hour") );
	
	bSizer14->Add( m_txtNetEveryDayStop, 0, wxALL, 1 );
	
	sbSizer9->Add( bSizer14, 0, wxEXPAND, 1 );
	
	m_rbtNetSpecialTimes = new wxRadioButton( m_panelNetwork, ID_RBTNETSPECIALTIMES, _("use network only as specified here:"), wxDefaultPosition, wxDefaultSize, 0);
	m_rbtNetSpecialTimes->SetToolTip( wxT("sets special network usage restrictions for checked days") );
	
	sbSizer9->Add( m_rbtNetSpecialTimes, 0, wxALL, 5 );
	
	m_panelNetSpecialTimes = new wxPanel( m_panelNetwork, ID_DEFAULT, wxDefaultPosition, wxDefaultSize, wxSUNKEN_BORDER|wxTAB_TRAVERSAL );
	m_panelNetSpecialTimes->SetExtraStyle( wxWS_EX_VALIDATE_RECURSIVELY );
	m_panelNetSpecialTimes->SetToolTip( wxT("use network on thursday") );
	
	wxBoxSizer* bSizer15;
	bSizer15 = new wxBoxSizer( wxVERTICAL );
	
	wxFlexGridSizer* fgSizer8;
	fgSizer8 = new wxFlexGridSizer( 4, 4, 0, 0 );
	fgSizer8->SetFlexibleDirection( wxHORIZONTAL );
	fgSizer8->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_chkNetMonday = new wxCheckBox( m_panelNetSpecialTimes, ID_CHKNETMONDAY, _("Monday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkNetMonday->SetToolTip( wxT("use network on monday") );
	
	fgSizer8->Add( m_chkNetMonday, 0, wxALL, 5 );
	
	m_txtNetMonday = new wxTextCtrl( m_panelNetSpecialTimes, ID_TXTNETMONDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer8->Add( m_txtNetMonday, 0, wxALL, 1 );
	
	m_chkNetTuesday = new wxCheckBox( m_panelNetSpecialTimes, ID_CHKNETTUESDAY, _("Tuesday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkNetTuesday->SetToolTip( wxT("use network on tuesday") );
	
	fgSizer8->Add( m_chkNetTuesday, 0, wxALL, 5 );
	
	m_txtNetTuesday = new wxTextCtrl( m_panelNetSpecialTimes, ID_TXTNETTUESDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer8->Add( m_txtNetTuesday, 0, wxALL, 1 );
	
	m_chkNetWednesday = new wxCheckBox( m_panelNetSpecialTimes, ID_CHKNETWEDNESDAY, _("Wednesday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkNetWednesday->SetToolTip( wxT("use network on wednesday") );
	
	fgSizer8->Add( m_chkNetWednesday, 0, wxALL, 5 );
	
	m_txtNetWednesday = new wxTextCtrl( m_panelNetSpecialTimes, ID_TXTNETWEDNESDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer8->Add( m_txtNetWednesday, 0, wxALL, 1 );
	
	m_chkNetThursday = new wxCheckBox( m_panelNetSpecialTimes, ID_CHKNETTHURSDAY, _("Thursday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	fgSizer8->Add( m_chkNetThursday, 0, wxALL, 5 );
	
	m_txtNetThursday = new wxTextCtrl( m_panelNetSpecialTimes, ID_TXTNETTHURSDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer8->Add( m_txtNetThursday, 0, wxALL, 1 );
	
	m_chkNetFriday = new wxCheckBox( m_panelNetSpecialTimes, ID_CHKNETFRIDAY, _("Friday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkNetFriday->SetToolTip( wxT("use network on friday") );
	
	fgSizer8->Add( m_chkNetFriday, 0, wxALL, 5 );
	
	m_txtNetFriday = new wxTextCtrl( m_panelNetSpecialTimes, ID_TXTNETFRIDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer8->Add( m_txtNetFriday, 0, wxALL, 1 );
	
	m_chkNetSaturday = new wxCheckBox( m_panelNetSpecialTimes, ID_CHKNETSATURDAY, _("Saturday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkNetSaturday->SetToolTip( wxT("use network on saturday") );
	
	fgSizer8->Add( m_chkNetSaturday, 0, wxALL, 5 );
	
	m_txtNetSaturday = new wxTextCtrl( m_panelNetSpecialTimes, ID_TXTNETSATURDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer8->Add( m_txtNetSaturday, 0, wxALL, 1 );
	
	m_chkNetSunday = new wxCheckBox( m_panelNetSpecialTimes, ID_CHKNETSUNDAY, _("Sunday"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkNetSunday->SetToolTip( wxT("use network on sunday") );
	
	fgSizer8->Add( m_chkNetSunday, 0, wxALL, 5 );
	
	m_txtNetSunday = new wxTextCtrl( m_panelNetSpecialTimes, ID_TXTNETSUNDAY, wxT(""), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer8->Add( m_txtNetSunday, 0, wxALL, 1 );
	
	bSizer15->Add( fgSizer8, 0, wxEXPAND, 1 );
	
	m_panelNetSpecialTimes->SetSizer( bSizer15 );
	m_panelNetSpecialTimes->Layout();
	bSizer15->Fit( m_panelNetSpecialTimes );
	sbSizer9->Add( m_panelNetSpecialTimes, 0, wxEXPAND | wxALL, 1 );
	
	bSizer12->Add( sbSizer9, 0, wxEXPAND, 1 );
	
	m_panelNetwork->SetSizer( bSizer12 );
	m_panelNetwork->Layout();
	bSizer12->Fit( m_panelNetwork );
	m_Notebook->AddPage( m_panelNetwork, _("network usage"), false );
	m_panelDiskAndMemory = new wxPanel( m_Notebook, ID_TABPAGE_DISK, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	m_panelDiskAndMemory->SetExtraStyle( wxWS_EX_VALIDATE_RECURSIVELY );
	
	wxBoxSizer* bSizer25;
	bSizer25 = new wxBoxSizer( wxVERTICAL );
	
	wxStaticBoxSizer* sbSizerDiskUsage;
	sbSizerDiskUsage = new wxStaticBoxSizer( new wxStaticBox( m_panelDiskAndMemory, -1, _("disk usage") ), wxVERTICAL );
	
	wxFlexGridSizer* fgSizerDiskUsage;
	fgSizerDiskUsage = new wxFlexGridSizer( 5, 3, 0, 0 );
	fgSizerDiskUsage->AddGrowableCol( 2 );
	fgSizerDiskUsage->SetFlexibleDirection( wxHORIZONTAL );
	fgSizerDiskUsage->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText40 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("use at most"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	fgSizerDiskUsage->Add( m_staticText40, 0, wxALL|wxEXPAND, 5 );
	
	m_txtDiskMaxSpace = new wxTextCtrl( m_panelDiskAndMemory, ID_TXTDISKMAXSPACE, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	m_txtDiskMaxSpace->SetToolTip( wxT("the maximum amount diskspace used by BOINC (in Gigabytes)") );
	
	fgSizerDiskUsage->Add( m_txtDiskMaxSpace, 0, wxALL, 1 );
	
	m_staticText41 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("Gigabytes disk space"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizerDiskUsage->Add( m_staticText41, 0, wxALL, 5 );
	
	m_staticText42 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("leave at least"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	fgSizerDiskUsage->Add( m_staticText42, 0, wxALL|wxEXPAND, 5 );
	
	m_txtDiskLeastFree = new wxTextCtrl( m_panelDiskAndMemory, ID_TXTDISKLEASTFREE, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	m_txtDiskLeastFree->SetToolTip( wxT("BOINC leaves at least this amount of diskspace free (in Gigagytes)") );
	
	fgSizerDiskUsage->Add( m_txtDiskLeastFree, 0, wxALL, 1 );
	
	m_staticText43 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("Gigabytes disk space free"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizerDiskUsage->Add( m_staticText43, 0, wxALL, 5 );
	
	m_staticText44 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("use at most"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	fgSizerDiskUsage->Add( m_staticText44, 0, wxALL|wxEXPAND, 5 );
	
	m_txtDiskMaxOfTotal = new wxTextCtrl( m_panelDiskAndMemory, ID_TXTDISKMAXOFTOTAL, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	m_txtDiskMaxOfTotal->SetToolTip( wxT("BOINC uses at most this percentage of total diskspace") );
	
	fgSizerDiskUsage->Add( m_txtDiskMaxOfTotal, 0, wxALL, 1 );
	
	m_staticText45 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("% of total disk space"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizerDiskUsage->Add( m_staticText45, 0, wxALL, 5 );
	
	m_staticText46 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("write to disk at most every"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	fgSizerDiskUsage->Add( m_staticText46, 0, wxALL|wxEXPAND, 5 );
	
	m_txtDiskWriteToDisk = new wxTextCtrl( m_panelDiskAndMemory, ID_TXTDISKWRITETODISK, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	fgSizerDiskUsage->Add( m_txtDiskWriteToDisk, 0, wxALL, 1 );
	
	m_staticText47 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("seconds"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizerDiskUsage->Add( m_staticText47, 0, wxALL, 5 );
	
	m_staticText48 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("use at most"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	fgSizerDiskUsage->Add( m_staticText48, 0, wxALL|wxEXPAND, 5 );
	
	m_txtDiskMaxSwap = new wxTextCtrl( m_panelDiskAndMemory, ID_TXTDISKWRITETODISK, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	fgSizerDiskUsage->Add( m_txtDiskMaxSwap, 0, wxALL, 1 );
	
	m_staticText49 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("% of page file (swap space)"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizerDiskUsage->Add( m_staticText49, 0, wxALL, 5 );
	
	sbSizerDiskUsage->Add( fgSizerDiskUsage, 0, wxEXPAND, 1 );
	
	bSizer25->Add( sbSizerDiskUsage, 0, wxEXPAND, 1 );
	
	wxStaticBoxSizer* sbSizerMemoryUsage;
	sbSizerMemoryUsage = new wxStaticBoxSizer( new wxStaticBox( m_panelDiskAndMemory, -1, _("memory usage") ), wxVERTICAL );
	
	wxFlexGridSizer* fgSizerMemoryUsage;
	fgSizerMemoryUsage = new wxFlexGridSizer( 3, 3, 0, 0 );
	fgSizerMemoryUsage->AddGrowableCol( 2 );
	fgSizerMemoryUsage->SetFlexibleDirection( wxHORIZONTAL );
	fgSizerMemoryUsage->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText50 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("use at most"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	fgSizerMemoryUsage->Add( m_staticText50, 0, wxALL|wxEXPAND, 5 );
	
	m_txtMemoryMaxInUse = new wxTextCtrl( m_panelDiskAndMemory, ID_TXTMEMORYMAXINUSE, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	fgSizerMemoryUsage->Add( m_txtMemoryMaxInUse, 0, wxALL, 1 );
	
	m_staticText51 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("% when computer is in use"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizerMemoryUsage->Add( m_staticText51, 0, wxALL, 5 );
	
	m_staticText52 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("use at most"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	fgSizerMemoryUsage->Add( m_staticText52, 0, wxALL|wxEXPAND, 5 );
	
	m_txtMemoryMaxOnIdle = new wxTextCtrl( m_panelDiskAndMemory, ID_TXTMEMORYMAXONIDLE, wxT(""), wxDefaultPosition, wxSize( 50,-1 ), wxTE_RIGHT );
	fgSizerMemoryUsage->Add( m_txtMemoryMaxOnIdle, 0, wxALL, 1 );
	
	m_staticText53 = new wxStaticText( m_panelDiskAndMemory, ID_DEFAULT, _("% when computer is idle"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizerMemoryUsage->Add( m_staticText53, 0, wxALL, 5 );
	
	sbSizerMemoryUsage->Add( fgSizerMemoryUsage, 0, wxEXPAND, 1 );
	
	m_chkMemoryWhileSuspended = new wxCheckBox( m_panelDiskAndMemory, ID_CHKMEMORYWHILESUSPENDED, _("leave applications in memory while suspended"), wxDefaultPosition, wxDefaultSize, 0 );
	
	m_chkMemoryWhileSuspended->SetToolTip( wxT("if checked, suspended work units leave in memory") );
	
	sbSizerMemoryUsage->Add( m_chkMemoryWhileSuspended, 0, wxALL, 5 );
	
	bSizer25->Add( sbSizerMemoryUsage, 0, wxALL|wxEXPAND, 1 );
	
	m_panelDiskAndMemory->SetSizer( bSizer25 );
	m_panelDiskAndMemory->Layout();
	bSizer25->Fit( m_panelDiskAndMemory );
	m_Notebook->AddPage( m_panelDiskAndMemory, _("disk and memory usage"), false );
	
	bSizer3->Add( m_Notebook, 1, wxEXPAND | wxALL, 1 );
	
	m_panelControls->SetSizer( bSizer3 );
	m_panelControls->Layout();
	bSizer3->Fit( m_panelControls );
	bSizer1->Add( m_panelControls, 1, wxALL|wxEXPAND, 1 );
	
	m_panelButtons = new wxPanel( this, ID_DEFAULT, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer5;
	bSizer5 = new wxBoxSizer( wxHORIZONTAL );
	
	m_btnOK = new wxButton( m_panelButtons, wxID_OK, _("OK"), wxDefaultPosition, wxDefaultSize, 0 );
	m_btnOK->SetToolTip( wxT("save all values and close the dialog") );
	
	bSizer5->Add( m_btnOK, 0, wxALL, 5 );
	
	m_btnCancel = new wxButton( m_panelButtons, wxID_CANCEL, _("Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
	m_btnCancel->SetToolTip( wxT("close the dialog without saving") );
	
	bSizer5->Add( m_btnCancel, 0, wxALL, 5 );
	
	m_btnHelp = new wxButton( m_panelButtons, wxID_HELP, _("Help"), wxDefaultPosition, wxDefaultSize, 0 );
	m_btnHelp->SetToolTip( wxT("shows the preferences web page") );
	
	bSizer5->Add( m_btnHelp, 0, wxALL, 5 );
	
	m_panelButtons->SetSizer( bSizer5 );
	m_panelButtons->Layout();
	bSizer5->Fit( m_panelButtons );
	bSizer1->Add( m_panelButtons, 0, wxALIGN_BOTTOM|wxALIGN_CENTER_HORIZONTAL|wxALL, 1 );
	
	this->SetSizer( bSizer1 );
	this->Layout();
}
