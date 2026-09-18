# Cloudflare ASN blocklist

Lista pública de ASN usados en reglas WAF de Cloudflare (`ip.src.asnum`) para sitios orientados a audiencia principalmente española.

> Severidad = evidencia observada en tráfico real (spray / volumen), no un scoring global de threat intel.

## Ficheros consultables

| Fichero | Uso |
|---|---|
| [`asns.json`](asns.json) | Fuente canónica (ASN, nombre, país, severidad, notas) |
| [`asns.txt`](asns.txt) | Un ASN por línea (fácil de parsear) |
| [`asns.csv`](asns.csv) | CSV |
| [`cloudflare-expression.txt`](cloudflare-expression.txt) | Expresión lista para pegar en una regla WAF Custom (`block`) |

### Ejemplo rápido

```bash
# Solo números
curl -fsSL https://raw.githubusercontent.com/mansildor/cloudflare-asn-blocklist/main/asns.txt

# JSON
curl -fsSL https://raw.githubusercontent.com/mansildor/cloudflare-asn-blocklist/main/asns.json
```

### Expresión Cloudflare (WAF Custom)

Acción recomendada: **Block**. Mantén aparte un `skip` para pasarelas de pago si aplica (p.ej. Redsys ASN 31627).

```
(ip.src.asnum eq 174) or (ip.src.asnum eq 6424) or (ip.src.asnum eq 6830) or (ip.src.asnum eq 9009) or (ip.src.asnum eq 11798) or (ip.src.asnum eq 13213) or (ip.src.asnum eq 18779) or (ip.src.asnum eq 20473) or (ip.src.asnum eq 30058) or (ip.src.asnum eq 36352) or (ip.src.asnum eq 40676) or (ip.src.asnum eq 43180) or (ip.src.asnum eq 50077) or (ip.src.asnum eq 132817) or (ip.src.asnum eq 199081) or (ip.src.asnum eq 200373) or (ip.src.asnum eq 202015) or (ip.src.asnum eq 202914) or (ip.src.asnum eq 203020) or (ip.src.asnum eq 203061) or (ip.src.asnum eq 205659) or (ip.src.asnum eq 207990) or (ip.src.asnum eq 212238) or (ip.src.asnum eq 393886) or (ip.src.asnum eq 394380) or (ip.src.asnum eq 394474) or (ip.src.asnum eq 396190) or (ip.src.asnum eq 401152)
```

## Listado

| ASN | Nombre | País | Severidad | Notas |
|---:|---|---|---|---|
| 9009 | M247 Europe | RO | **high** | VPN/hosting; mucho spray (muchas IPs con 1–2 req). |
| 30058 | FDCServers | US | **high** | Spray claro (decenas de IPs a 1–2 req). |
| 36352 | HostPapa / ColoCrossing | US | **high** | Spray en 23.95.163.0/24 y 198.46.220.0/24. |
| 40676 | Psychz Networks | US | **high** | Hosting frecuentemente abusado. |
| 200373 | 3xK Tech GmbH | DE | **high** | Más agresivo observado: ~11k req desde 1–2 IPs. |
| 203020 | HostRoyale Technologies | IN | **high** | Mucho spray multi-prefijo. |
| 207990 | HostRoyale (customer) | IN | **high** | Spray asociado a HostRoyale. |
| 212238 | Datacamp / CDNEXT | GB | **high** | Proxy/CDN abusado; mucho spray. |
| 396190 | Leaseweb USA (Seattle) | US | **high** | Spray en 152.163.4.0/22 y 152.163.216.0/22. |
| 6424 | EDGOO Networks | PT | **medium** | Hosting y redes; asociado a abuso y scrapers. |
| 11798 | Ace Data Centers | US | **medium** | Datacenter US; spray en varios prefijos. |
| 13213 | THG Hosting / UK2 | GB | **medium** | Hosting UK. |
| 18779 | EGIHosting | US | **medium** | Hosting US. |
| 20473 | Vultr (Constant Company) | US | **medium** | VPS popular; abuso frecuente de scrapers. |
| 43180 | Trunk Networks | SC | **medium** | Volumen bajo; patrón spray en prefijos compartidos. |
| 50077 | SYN LTD | GB | **medium** | Hosting. |
| 132817 | DZCRD Networks | BD | **medium** | Redes APAC; hosting/transitación dudosa. |
| 199081 | Lancom Ltd. | GR | **medium** | Spray bajo (p.ej. 92.112.83.0/24). |
| 202015 | HZ Hosting | BG | **medium** | Hosting BG. |
| 202914 | Adeo Datacenter | DK | **medium** | Volumen bajo; prefijo compartido. |
| 203061 | UAB code200 | LT | **medium** | Hosting LT. |
| 205659 | UAB code200 (ISP2) | LT | **medium** | Hosting LT (mismo grupo code200). |
| 393886 | Leaseweb USA (Miami) | US | **medium** | Familia Leaseweb USA; spray bajo. |
| 394380 | Leaseweb USA (Dallas) | US | **medium** | Familia Leaseweb USA. |
| 394474 | WhiteLabelColo | US | **medium** | Spray en 167.250.108.0/22. |
| 401152 | Ace Data Centers II | US | **medium** | Spray en 108.165.172.0/24. |
| 174 | Cogent Communications | US | **low** | Backbone/tránsito. Volumen bajo en sitios ES; bloqueo por ruido internacional. |
| 6830 | Liberty Global Europe | NL | **low** | ISP europeo grande; revisar si afecta clientes reales. |


## Severidad

- **high** — Agresivo o mucho spray (muchas IPs con 1–2 peticiones, o pocas IPs con miles de peticiones).
- **medium** — Hosting/VPS dudoso con abuso moderado.
- **low** — Poco volumen o ASN muy amplio (tránsito/ISP); valora falsos positivos.

## Aviso

Bloquear ASN de tránsito grande (p.ej. Cogent AS174) o ISPs europeos puede afectar usuarios legítimos (VPN, empresas, hosting compartido). Úsalo bajo tu responsabilidad. Esta lista no es consejo legal ni garantía de seguridad.

## Licencia

CC0 1.0 (dominio público / uso libre).
