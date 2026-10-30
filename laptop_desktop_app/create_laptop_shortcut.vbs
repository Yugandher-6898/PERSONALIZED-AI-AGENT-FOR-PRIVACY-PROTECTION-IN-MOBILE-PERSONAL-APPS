Set WshShell = CreateObject("WScript.Shell")
strDesktop = WshShell.SpecialFolders("Desktop")
Set oShortcut = WshShell.CreateShortcut(strDesktop & "\CyberShield AI - Laptop SOC.lnk")
oShortcut.TargetPath = "C:\Users\gadup\Desktop\2.1 ADD\AI GEN\laptop_desktop_app\CyberShield_Laptop.exe"
oShortcut.Arguments = ""
oShortcut.WorkingDirectory = "C:\Users\gadup\Desktop\2.1 ADD\AI GEN\laptop_desktop_app"
oShortcut.WindowStyle = 1
oShortcut.Description = "CyberShield AI - Multi-Device Laptop SOC & Mobile Monitor"
oShortcut.IconLocation = "C:\Users\gadup\Desktop\2.1 ADD\AI GEN\laptop_desktop_app\desktop_ui\static\icon.ico,0"
oShortcut.Save
WScript.Echo "Shortcut created: " & oShortcut.FullName
