---
title: Wireshark tool suite bits
date: 2023-03-10
tags:
  - wireshark
  - forensics
  - network
  - tshark
---
# Official Documentation
- [tshark official documentation](https://www.wireshark.org/docs/man-pages/tshark.html)
# `tshark` Bits 

## Dumping form data in HTTP requests packet

```bash
tshark -r meerkat.pcap -Y "http.request.uri == \"/bonita/loginservice\"" -e urlencoded-form.key -e urlencoded-form.value -Tfields
username,password,_l    install,install,en
username,password,_l    Clerc.Killich@forela.co.uk,vYdwoVhGIwJ,en
username,password,_l    install,install,en
username,password,_l    Lauren.Pirozzi@forela.co.uk,wsp0Uy,en
username,password,_l    install,install,en
username,password,_l    Merna.Rammell@forela.co.uk,u7pWoF36fn,en
...
```

> [!WARNING]- Currently, there's no way to convert HTTP POST form data into a csv without manual processing.
> All values are getting treated as a single string instead of being mapped to their key.

Multiple output formats can be used but I found the json and ek and to be the most interesting.
### JSON format output
The output format can be manipulated easily using `jq` be can be really tedious when dealing with HTTP POST data.
```bash
tshark -T json -e urlencoded-form.key -e urlencoded-form.value | jq '{"username": .[]._source.layers."urlencoded-form.value"[0], "password": .[]._source.layers."urlencoded-form.value"[1]}'
```

```json  {title="Command output"}
...
{
  "username": "Gianina.Tampling@forela.co.uk",
  "password": "TQSNp6XrK"
}
{
  "username": "Gianina.Tampling@forela.co.uk",
  "password": "install"
}
...
```

### EK format output

> [!INFO] WIP
