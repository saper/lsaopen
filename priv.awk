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
BEGIN {
	maxprivlen = 0
}
{
	printf("%-40s	DW L'%s', 0\r\n", $0, $0);
	if (maxprivlen < length($0)) { maxprivlen = length($0); }
}
END {
	printf("\r\n%-40s	DD %dD\r\n", "MAXPRIVNAMELEN", maxprivlen);
}
