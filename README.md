# Xmap - a capable, lightweight, reflected cross-site-scripting vulnerability scanner

The purpose of *Xmap* is to find cross site scripting vulnerabilities in url parameters. It uses a straightforward, brute-force-ish approach that works for
most of the regular sites you want to test. This gives any web developer the capability to protect his own site from potential annoying XSS holes.

## Example Usage:
### ./xmap.py -t "http://sudo.co.il/xss/level0.php?email=#"
### python3 xmap.py -t target_site -c -l 3 -v -b