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
