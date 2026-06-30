rule caliber44 {
   meta:
      description = "This rule detects unpacked 44caliber malware samples."
      Reference = "38957fb3708884f1a8befb0c17b0fa81f57005a5de058772cc12bf357c548eab"
      author = "Michelle Khalil @apophis133"
      date = "2026-06-30"
   
   strings:
        $x1 = "\\44CALIBER" ascii

        $s1 = ":eye: IP:" wide
        $s2 = ":file_folder: Grabbed Files" wide
        $s3 = ":cookie: Cookies -" fullword ascii wide
        $s4 = ":credit_card: CC -" fullword ascii wide
        $s5 = ":spy: NEW LOG FROM -" fullword ascii wide
        $s6 = ":key: Passwords -" fullword ascii wide
        $s7 = ":notepad_spiral: AutoFills -" fullword ascii wide

    condition:
        uint16(0) == 0x5a4d and
        all of them
}
