rule PAS_PHP_WEBSHELL
{
    meta:
        description = "PAS TOOL PHP WEBSHELL"
        author = "backcountryinfosec"
        date = "2018-08-17"
    strings:
        $x1 = "2410985280"

        $s1 = "<?php" nocase
        $s2 = "if(!EMPTY" nocase ascii
        $s3 = "gzuncompress" nocase  ascii
        $s4 = "_cook" nocase  ascii
        $s5 = "0xffffffff" nocase
        $s6 = "crc32(substr" nocase ascii
        $s7 = "=';"
        $s8 = "create_function" nocase
        $s9 = "66154,5551,2752"


   condition:
       uint16(0) == 0x3f3c and
        filesize > 50KB and filesize < 100KB and
        ( 1 of ($x*) or 5 of ($s*))
        or all of them
}
