' ScamHunter Desk -- start in the background with no console window,
' so closing a window can't stop the watchers. Open the Desk from the
' "ScamHunter Desk" shortcut (http://127.0.0.1:8787/).
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
Set sh = CreateObject("WScript.Shell")
sh.CurrentDirectory = here
sh.Run "cmd /c """ & here & "\run_desk.cmd"" --no-open", 0, False
