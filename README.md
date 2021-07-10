# ROPemporium

All binaries from ROPemporium website [https://ropemporium.com](https://ropemporium.com/), categorized by architecture, with custom flags and solving scripts. I actually solved all the challenges only in x86 and x64 but I'll maybe:tm: touch to ARM and MIPS versions soon :grin:

You can btw check my (french) blog were I will explain how I solved the challenges in the differents architectures : [https://www.soeasy.re](https://www.soeasy.re) :smile:

<table>
  <thead>
    <tr>
      <td align="center">Challenge</td>
      <td align="center">Architecture</td>
      <td align="center">Solving script</td>
  </thead>
	<tbody>
		<tr>
			<td  align="center" rowspan="4">0 - ret2win</td>
			<td align="center">x86</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">x86_64</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">ARM</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">MIPS</td>
			<td align="center">:white_check_mark:</td>
		</tr>
    <tr>
			<td  align="center" rowspan="4">1 - split</td>
			<td align="center">x86</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">x86_64</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">ARM</td>
			<td align="center">:large_orange_diamond:</td>
		</tr>
		<tr>
			<td align="center">MIPS</td>
			<td align="center">:x:</td>
		</tr>
    <tr>
			<td  align="center" rowspan="4">2 - callme</td>
			<td align="center">x86</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">x86_64</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">ARM</td>
			<td align="center">:x:</td>
		</tr>
		<tr>
			<td align="center">MIPS</td>
			<td align="center">:x:</td>
		</tr>
    <tr>
			<td  align="center" rowspan="4">3 - write4</td>
			<td align="center">x86</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">x86_64</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">ARM</td>
			<td align="center">:x:</td>
		</tr>
		<tr>
			<td align="center">MIPS</td>
			<td align="center">:x:</td>
		</tr>
    <tr>
			<td  align="center" rowspan="4">4 - badchars</td>
			<td align="center">x86</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">x86_64</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">ARM</td>
			<td align="center">:x:</td>
		</tr>
		<tr>
			<td align="center">MIPS</td>
			<td align="center">:x:</td>
		</tr>
     <tr>
			<td  align="center" rowspan="4">5 - fluff</td>
			<td align="center">x86</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">x86_64</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">ARM</td>
			<td align="center">:x:</td>
		</tr>
		<tr>
			<td align="center">MIPS</td>
			<td align="center">:x:</td>
		</tr>
     <tr>
			<td  align="center" rowspan="4">6 - pivot</td>
			<td align="center">x86</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">x86_64</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">ARM</td>
			<td align="center">:x:</td>
		</tr>
		<tr>
			<td align="center">MIPS</td>
			<td align="center">:x:</td>
		</tr>
     <tr>
			<td  align="center" rowspan="4">7 - ret2csu</td>
			<td align="center">x86_64</td>
			<td align="center">:white_check_mark:</td>
		</tr>
		<tr>
			<td align="center">ARM</td>
			<td align="center">:x:</td>
		</tr>
		<tr>
			<td align="center">MIPS</td>
			<td align="center">:x:</td>
		</tr>
	</tbody>
</table>

## TODO

- Write solving articles on [https://www.soeasy.re](https://www.soeasy.re)
- ARM et MIPS versions :grin:

## Contribution

Feel free to contribute and propose your solving scripts for some MIPS and ARM versions of challenges :blush:
