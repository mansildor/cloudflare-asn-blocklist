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
(ip.src.asnum eq 174) or (ip.src.asnum eq 1207) or (ip.src.asnum eq 5065) or (ip.src.asnum eq 5739) or (ip.src.asnum eq 7979) or (ip.src.asnum eq 9009) or (ip.src.asnum eq 11798) or (ip.src.asnum eq 14061) or (ip.src.asnum eq 17497) or (ip.src.asnum eq 18779) or (ip.src.asnum eq 19318) or (ip.src.asnum eq 20473) or (ip.src.asnum eq 23033) or (ip.src.asnum eq 26658) or (ip.src.asnum eq 27411) or (ip.src.asnum eq 30058) or (ip.src.asnum eq 36352) or (ip.src.asnum eq 39600) or (ip.src.asnum eq 46261) or (ip.src.asnum eq 46635) or (ip.src.asnum eq 47007) or (ip.src.asnum eq 51167) or (ip.src.asnum eq 53856) or (ip.src.asnum eq 55286) or (ip.src.asnum eq 62874) or (ip.src.asnum eq 63023) or (ip.src.asnum eq 64249) or (ip.src.asnum eq 132203) or (ip.src.asnum eq 132817) or (ip.src.asnum eq 136787) or (ip.src.asnum eq 137409) or (ip.src.asnum eq 142430) or (ip.src.asnum eq 142622) or (ip.src.asnum eq 197170) or (ip.src.asnum eq 197540) or (ip.src.asnum eq 200373) or (ip.src.asnum eq 201341) or (ip.src.asnum eq 202412) or (ip.src.asnum eq 203020) or (ip.src.asnum eq 204287) or (ip.src.asnum eq 204646) or (ip.src.asnum eq 206092) or (ip.src.asnum eq 207043) or (ip.src.asnum eq 207990) or (ip.src.asnum eq 209372) or (ip.src.asnum eq 210906) or (ip.src.asnum eq 211680) or (ip.src.asnum eq 212238) or (ip.src.asnum eq 213541) or (ip.src.asnum eq 215703) or (ip.src.asnum eq 263740) or (ip.src.asnum eq 393886) or (ip.src.asnum eq 394380) or (ip.src.asnum eq 394474) or (ip.src.asnum eq 396319) or (ip.src.asnum eq 396356) or (ip.src.asnum eq 398781) or (ip.src.asnum eq 399073) or (ip.src.asnum eq 400529) or (ip.src.asnum eq 401152) or (ip.src.asnum eq 401560)
```

### Rangos IP adicionales

La regla desplegada añade, con OR, rangos IP de un scraper distribuido mediante proxies (atribuidos a AS22773 Cox; el ASN no se bloquea por ser ISP residencial). Cada /24 cubre solo IPs observadas (propuestas 2026-10-16, 2026-10-20 y 2026-10-22; 45 rangos). Además se bloquea la IP individual `2a06:98c0:3600::103` (Cloudflare Workers, scraper ThreadLabsResearch; el ASN 132892 no se bloquea) (propuesta 2026-10-24). Total: 46 entradas:

```
(ip.src in {45.206.85.0/24 45.206.116.0/24 45.206.124.0/24 45.206.126.0/24 45.207.184.0/24 45.207.189.0/24 154.85.5.0/24 154.94.32.0/24 154.94.40.0/24 154.94.59.0/24 154.94.63.0/24 154.198.15.0/24 156.229.53.0/24 156.233.126.0/24 156.239.59.0/24 156.241.41.0/24 156.242.22.0/24 156.243.97.0/24 156.243.196.0/24 156.244.154.0/24 156.244.155.0/24 156.248.31.0/24 156.248.104.0/24 156.248.111.0/24 156.249.20.0/24 156.249.23.0/24 156.249.52.0/24 156.249.53.0/24 156.249.121.0/24 45.206.88.0/24 45.206.118.0/24 45.206.122.0/24 45.207.177.0/24 154.94.56.0/24 154.194.3.0/24 156.229.52.0/24 156.233.42.0/24 156.239.146.0/24 156.243.35.0/24 156.243.198.0/24 156.244.147.0/24 156.244.149.0/24 156.244.157.0/24 37.19.64.0/24 37.19.65.0/24 2a06:98c0:3600::103})
```

En producción la lista de ASN se escribe en forma compacta `(ip.src.asnum in {...})` para respetar el límite de 4096 caracteres por expresión.

## Listado

| ASN | Nombre | País | Severidad | Notas |
|---:|---|---|---|---|
| 7979 | Servers.com | US | **high** | Hosting; patrón spray. |
| 9009 | M247 Europe | RO | **high** | VPN/hosting; mucho spray (muchas IPs con 1–2 req). |
| 14061 | DigitalOcean | US | **high** | VPS grande; abuso observado; posible falso positivo en automatismos legítimos. |
| 26658 | Hengtong IDC | US | **high** | Hosting; patrón spray. |
| 30058 | FDCServers | US | **high** | Spray claro (decenas de IPs a 1–2 req). |
| 36352 | HostPapa / ColoCrossing | US | **high** | Spray en 23.95.163.0/24 y 198.46.220.0/24. |
| 46261 | QuickPacket | US | **high** | Hosting; spray claro multi-IP. |
| 46635 | Contact Consumers (NET3-AI) | US | **high** | Hosting; patrón agresivo (propuesta 2026-10-07). |
| 47007 | Colocation America | US | **high** | Hosting; patrón spray. |
| 63023 | GTHost / GLOBALTELEHOST | US | **high** | Hosting; patrón agresivo (propuesta 2026-10-12/13). |
| 132203 | Tencent Cloud (TENCENT-NET-AP-CN) | CN | **high** | Cloud/hosting; patrón agresivo (propuesta 2026-10-07). |
| 142430 | DIGI VPS | IN | **high** | Hosting; tráfico agresivo concentrado en pocas IPs. |
| 200373 | 3xK Tech GmbH | DE | **high** | Más agresivo observado: ~11k req desde 1–2 IPs. |
| 201341 | trafficforce / Centurion | LT | **high** | Hosting; patrón spray multi-IP. |
| 202412 | Omegatech LTD | SC | **high** | Hosting; patrón agresivo (propuesta 2026-10-12/13). |
| 203020 | HostRoyale Technologies | IN | **high** | Mucho spray multi-prefijo. |
| 204287 | HostRoyale Technologies | IN | **high** | Hosting; asociado a HostRoyale. |
| 206092 | SECFIREWALLAS / F.N.S. HOLDINGS LIMITED | US | **high** | Hosting; spray WP webshell/plugins agresivo (propuesta 2026-10-14). |
| 207043 | Dedik Services | GB | **high** | Hosting; tráfico agresivo concentrado en pocas IPs. |
| 207990 | HostRoyale (customer) | IN | **high** | Spray asociado a HostRoyale. |
| 212238 | Datacamp / CDNEXT | GB | **high** | Proxy/CDN abusado; mucho spray. |
| 396319 | Oxylabs | US | **high** | Proxy/residencial; scrapers. |
| 396356 | Latitude.sh | US | **high** | Hosting; patrón spray. |
| 398781 | Oculus Networks | US | **high** | Hosting; patrón spray. |
| 1207 | Pittsburgh Supercomputing Center (PSC) | US | **medium** | Universidad/HPC; Chrome headless/148 en vizcaino, 686 req desde 128.182.81.33 (propuesta 2026-10-26). |
| 5065 | Bunny Communications | US | **medium** | Hosting/proxy; abuso moderado (propuesta 2026-10-07). |
| 5739 | University of California Santa Cruz (UCSC) | US | **medium** | Universidad; escáner PHP-Version-Research, 292 req desde 169.233.63.17 (propuesta 2026-10-26). |
| 11798 | Ace Data Centers | US | **medium** | Datacenter US; spray en varios prefijos. |
| 17497 | Liasail Global Hongkong | HK | **medium** | Hosting; fetch de imágenes / abuso moderado. |
| 18779 | EGIHosting | US | **medium** | Hosting US. |
| 19318 | Interserver | US | **medium** | Hosting US; probes de wp-config en vizcaino (propuesta 2026-10-30). |
| 20473 | Vultr (Constant Company) | US | **medium** | VPS popular; abuso frecuente de scrapers. |
| 27411 | Leaseweb USA (Chicago) | US | **medium** | Familia Leaseweb USA. |
| 23033 | Wowrack | US | **medium** | Hosting; DotBot (Moz) agresivo (propuesta 2026-10-21). |
| 39600 | BUNNY TECHNOLOGY LLC | US | **medium** | Hosting/proxy; abuso moderado (propuesta 2026-10-07). |
| 51167 | Contabo GmbH | DE | **medium** | VPS grande; scrape de imágenes de producto; posible falso positivo. |
| 53856 | NJ IX | US | **medium** | Hosting/IX; volumen moderado. |
| 55286 | SERVER-MANIA | CA | **medium** | Hosting; granja de bots distribuida (muchas IPs). |
| 62874 | Web2Objects | US | **medium** | Hosting; volumen moderado. |
| 64249 | Endoffice | US | **medium** | Hosting; volumen moderado. |
| 132817 | DZCRD Networks | BD | **medium** | Redes APAC; hosting/transitación dudosa. |
| 136787 | PacketHub S.A. | PA | **medium** | VPN/proxy hosting; volumen alto en pocas IPs. |
| 137409 | GSL Networks | AU | **medium** | Hosting/proxy; ~2.5k req sin User-Agent en vizcaino (propuesta 2026-10-30). |
| 142622 | Dream Information Laboratory | JP | **medium** | Hosting; abuso moderado (propuesta 2026-10-07). |
| 197170 | TechTies Inc. | SC | **medium** | Hosting; tráfico concentrado en pocas IPs. |
| 204646 | web2objects (customer) | US | **medium** | Hosting; asociado a Web2Objects. |
| 209372 | WS Telecom customers | US | **medium** | Clientes WS Telecom; hosting/proxy. |
| 210906 | UAB Bite Lietuva (BITE-US) | LT | **medium** | Hosting/proxy; abuso moderado (propuesta 2026-10-07). |
| 211680 | BitSight / NSEC | PT | **medium** | Escáner de reputación; tráfico de probes. |
| 213541 | WS Telecom Inc | US | **medium** | Salida VPN/proxy; patrón multi-IP (posible falso positivo). |
| 197540 | netcup GmbH | DE | **medium** | Hosting; MJ12bot en listados de categoría (propuesta 2026-10-21). |
| 215703 | FreakHosting | GB | **medium** | Hosting; tráfico de bots/scraper (propuesta 2026-10-22). |
| 263740 | Corporacion Laceibanetsociety | HN | **medium** | Hosting; abuso moderado (propuesta 2026-10-07). |
| 393886 | Leaseweb USA (Miami) | US | **medium** | Familia Leaseweb USA; spray bajo. |
| 394380 | Leaseweb USA (Dallas) | US | **medium** | Familia Leaseweb USA. |
| 394474 | WhiteLabelColo | US | **medium** | Spray en 167.250.108.0/22. |
| 399073 | BUNNY TECHNOLOGY LLC (TBB-ASN) | US | **medium** | Hosting/proxy; abuso moderado (propuesta 2026-10-07). |
| 400529 | Infraly LLC | US | **medium** | Hosting; volumen moderado. |
| 401152 | Ace Data Centers II | US | **medium** | Spray en 108.165.172.0/24. |
| 401560 | OneCable Network | US | **medium** | Hosting/proxy; volumen alto multi-IP. |
| 174 | Cogent Communications | US | **low** | Backbone/tránsito. Volumen bajo en sitios ES; bloqueo por ruido internacional. |

## Severidad

- **high** — Agresivo o mucho spray (muchas IPs con 1–2 peticiones, o pocas IPs con miles de peticiones).
- **medium** — Hosting/VPS dudoso con abuso moderado.
- **low** — Poco volumen o ASN muy amplio (tránsito/ISP); valora falsos positivos.

## Aviso

Bloquear ASN de tránsito grande (p.ej. Cogent AS174) o ISPs europeos puede afectar usuarios legítimos (VPN, empresas, hosting compartido). Úsalo bajo tu responsabilidad. Esta lista no es consejo legal ni garantía de seguridad.

## Licencia

CC0 1.0 (dominio público / uso libre).
