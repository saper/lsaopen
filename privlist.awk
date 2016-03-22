BEGIN {  printf("PRIVILEGES:\r\n");    }
{        printf("	LsaUnicodeStr <SIZEOF %s - 2, SIZEOF %s, %s>\r\n", $0, $0, $0); }
END {    printf("END_OF_PRIVILEGES:\r\n");      }
