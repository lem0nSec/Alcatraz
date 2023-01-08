rule Vir_Alcatraz: Alcatraz
{
        meta:
        description = "Alcatraz_detection_rule"
        author = "Angelo Frasca Caccia (@lem0nSec_)"
        date = "01/07/2023"
                hash = "4a53edee6f545f3763f3190b73ef5631a0bb1899642a2870ed3538f16926eb44" // sha256


        strings:
                $signature = "alca" ascii
                $final_pattern = { 3E 49 83 3C 03 00 75 0C 3E 4D 87 2C 03 3E 4D 87 74 03 08 C3 48 83 C0 10 EB E6 3E 49 83 3C 03 00 74 12 4D 31 ED 4D 89 EE 3E 4D 87 2C 03 3E 4D 87 74 03 08 C3 48 83 E8 10 EB E0 }
                


        condition:
                uint16(0) == 0x5A4D and ($final_pattern or ($signature at 0x2CF))


}
