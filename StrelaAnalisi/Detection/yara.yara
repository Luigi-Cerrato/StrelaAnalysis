rule HostBased {
    meta:
        description = "Generic Rule to detect the StrelaStealer"
    strings:
        $mz = { 4d 5a }
    
        $s0 = "http://yandex.com" ascii wide
        $s1 = "http://crl.comodoca.com/AAACertificateServices.crl04" ascii wide
        $s2 = "http://ocsp.comodoca.com" ascii wide
        $s3 = "http://crl.sectigo.com/SectigoPublicCodeSigningRootR46.crl0" ascii wide
        $s4 = "http://crt.sectigo.com/SectigoPublicCodeSigningRootR46.p7c0#" ascii wide
        $s5 = "http://ocsp.sectigo.com" ascii wide
        $s6 = "https://sectigo.com/CPS0" ascii wide
        $s7 = "http://crl.sectigo.com/SectigoPublicCodeSigningCAR36.crl0y" ascii wide
        $s8 = "http://crt.sectigo.com/SectigoPublicCodeSigningCAR36.crt0#" ascii wide
        $s9 = "http://ocsp.sectigo.com" ascii wide
        
        $x0 = "Kernel32" ascii wide
        $x1 = "VirtualAlloc" ascii wide
        $x2 = "GetProcAddress" ascii wide
        $x3 = "VirtualQuery failed for %d bytes at address %p" ascii wide
        $x4 = "VirtualProtect failed with code 0x%x" ascii wide
        $x5 = "InternetCheckConnectionA" ascii wide
    condition:
        ( $mz at 0 ) and ( 1 of ($s*) ) or ( 3 of ($x*) )
}
