' ScamHunter Desk -- what the Desktop and Start Menu icons run.
' If the Desk is already running, just opens the dashboard.
' If it isn't (crashed, stopped, or never started this session), starts it
' quietly first, waits for it to answer, then opens the dashboard.
Option Explicit
Dim fso, sh, here, url, i
url = "http://127.0.0.1:8787/"
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
here = fso.GetParentFolderName(WScript.ScriptFullName)

Function DeskUp()
  Dim http
  DeskUp = False
  On Error Resume Next
  Set http = CreateObject("MSXML2.ServerXMLHTTP.6.0")
  http.setTimeouts 2000, 2000, 2000, 2000
  http.open "GET", url, False
  http.send
  If Err.Number = 0 Then
    If http.status > 0 And http.status < 500 Then DeskUp = True
  End If
  On Error GoTo 0
End Function

If Not DeskUp() Then
  sh.CurrentDirectory = here
  sh.Run "wscript.exe """ & here & "\run_desk_hidden.vbs""", 0, False
  For i = 1 To 30            ' up to about 30 seconds
    WScript.Sleep 1000
    If DeskUp() Then Exit For
  Next
  If Not DeskUp() Then
    MsgBox "ScamHunter Desk didn't start within 30 seconds." & vbCrLf & vbCrLf & _
           "See desk.log in " & here & " for the reason.", vbExclamation, "ScamHunter Desk"
    WScript.Quit 1
  End If
End If
sh.Run url
