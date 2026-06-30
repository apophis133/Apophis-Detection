rule caliber44 {
   meta:
      description = "This rule detects unpacked 44caliber malware samples."
      Reference = "38957fb3708884f1a8befb0c17b0fa81f57005a5de058772cc12bf357c548eab"
      author      = "Michelle Khalil @apophis133"
      date        = "2026-06-30"
   
   strings:
        $x1 = "\\44CALIBER" ascii

        $s1 = ":eye: IP:" fullword wide
        $s2 = ":file_folder: Grabbed Files" fullword wide
        $s3 = ":cookie: Cookies -" fullword wide
        $s4 = ":credit_card: CC -" fullword wide
        $s5 = ":spy: NEW LOG FROM -" fullword wide
        $s6 = ":key: Passwords -" fullword wide
        $s7 = ":notepad_spiral: AutoFills -" fullword wide

    condition:
        uint16(0) == 0x5a4d and
        all of them
}
