/*
   Yara Rule Set
   Author: BackcountryInfosec
   Date: 2018-06-22
   Identifier: spyware
*/

/* Rule Set ----------------------------------------------------------------- */

rule RedShell {
   meta:
      description = "Spyware - file RedShell.dll"
      author = "BackcountryInfosec"
      reference = "https://www.pcgamer.com/red-shell-analytics-software-causes-privacy-uproar-over-a-dozen-developers-vow-to-drop-it/"
      date = "2018-06-22"
      hash = "12d107d4edcd64e345a0922946ec30a5e02bb8c6f750adabc9a4dbe7781712d5"

   strings:
      $x1 = "C:\\Users\\rober\\OneDrive\\Documents\\GitHub\\red-shell\\x64\\Release\\RedShell.pdb" fullword ascii
      $x2 = "RedShell.dll" fullword ascii
      $x3 = "C:\\Users\\rober" ascii
      $s4 = "?getUserID@RedShell@Innervate@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ" fullword ascii
      $s5 = "?getApiKey@RedShell@Innervate@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ" fullword ascii
      $s6 = "Setting autologon policy to WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH" fullword ascii
      $s7 = "Incorrect Content-Type: must be textual to extract_string, JSON to extract_json." fullword wide
      $s8 = "this combination of modes on container stream not supported" fullword ascii
      $s9 = "?VERSION@RedShell@Innervate@@0V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@A" fullword ascii
      $s10 = "?API_KEY@RedShell@Innervate@@0V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@A" fullword ascii
      $s11 = "?USER_ID@RedShell@Innervate@@0V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@A" fullword ascii
      $s12 = "?logEvent@RedShell@Innervate@@SAXPEAD@Z" fullword ascii
      $s13 = "?getDebug@RedShell@Innervate@@SA_NXZ" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 2000KB and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}


