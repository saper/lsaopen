#------------------------------------------------------------------
#
#   Enumerate Microsoft Windows Local Security Authority privileges
#   Copyright (C) 2016	  Marcin Cieslak <saper@saper.info>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program in the COPYING file.  
#   If not, see <http://www.gnu.org/licenses/>.
#
#------------------------------------------------------------------
BEGIN {  printf("PRIVILEGES:\r\n");    }
{        printf("	LsaUnicodeStr <SIZEOF %s - 2, SIZEOF %s, %s>\r\n", $0, $0, $0); }
END {
         printf("END_OF_PRIVILEGES:\r\n");
         printf("	LsaUnicodeStr <0, 0, 0>\r\n");
}
