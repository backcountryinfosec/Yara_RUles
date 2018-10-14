import "pe"

rule tasksched_dllinject {
   meta:
      description = "Detects DLL Injec from released POC"
      reference = "https://www.tomshardware.com/news/windows-10-zero-day-exposed-twitter,37709.html"
      date = "2018-08-29"
      hash1 = "e7e44cd2daf4f5b67072d9e66f76387e92374160059d924ee62eb358fe12b3dc"
   strings:
      $x1 = "D:\\IE11SandboxEscapes-master\\x64\\Release\\InjectDll.pdb" fullword ascii
      $x2 = "Specify -l to list all IE processes running in the current session" fullword ascii
      $x3 = "Usage: InjectDll -l|pid PathToDll" fullword ascii
      $x4 = "Injecting DLL: %ls into PID: %d" fullword ascii
      $s5 = "Error listing processes: %d" fullword ascii
      $s6 = ".?AV?$_Ref_count@UIEProcessEntry@@@std@@" fullword ascii
      $s7 = "Couldn't write to process memory" fullword ascii
      $s8 = "Couldn't open process %d" fullword ascii
      $s9 = "Couldn't allocate memory in process" fullword ascii
      $s10 = "Couldn't create remote thread %d" fullword ascii
      $s11 = "Error adjusting privilege %d" fullword ascii
      $s12 = "|-- [%d] - %s" fullword ascii
      $s13 = "[%d] - %s" fullword ascii
      $s14 = "Error 1 %d" fullword ascii
      $s15 = "Not all privilges available" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 400KB and
        pe.imphash() == "cd84a6088199652eaa52dd42902ff885" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

