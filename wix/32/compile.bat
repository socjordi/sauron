signtool sign /fd sha256 /td sha256 /ac ..\certificats\comodorsacertificationauthority_kmod.crt /f ..\certificats\0081F763CBC570B0FAF1B5ACDD597D88FC.crt /tr http://timestamp.comodoca.com/ ProcessMonitorDriver.sys
signtool sign /fd sha256 /td sha256 /ac ..\certificats\comodorsacertificationauthority_kmod.crt /f ..\certificats\0081F763CBC570B0FAF1B5ACDD597D88FC.crt /tr http://timestamp.comodoca.com/ FileMonitorDriver.sys
signtool sign /fd sha256 /td sha256 /ac ..\certificats\comodorsacertificationauthority_kmod.crt /f ..\certificats\0081F763CBC570B0FAF1B5ACDD597D88FC.crt /tr http://timestamp.comodoca.com/ sauron.exe
signtool sign /fd sha256 /td sha256 /ac ..\certificats\comodorsacertificationauthority_kmod.crt /f ..\certificats\0081F763CBC570B0FAF1B5ACDD597D88FC.crt /tr http://timestamp.comodoca.com/ sauronwatch.exe
candle.exe sauron.wxs
light.exe sauron.wixobj
copy sauron.msi \\vboxsrv\dades\sauron\32
@rem ..\winscp.com /script="winscp.txt"