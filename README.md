# Block-NXInternet

Bloqueia o acesso à internet do **Siemens NX** no Windows, criando regras de saída
(*outbound*) no Firewall do Windows Defender — uma regra por executável do NX.

Feito para instalações com **licença local (nodelocked)**. Tráfego de loopback não é
filtrado pelo Firewall do Windows, então o licenciamento local continua funcionando
normalmente com o bloqueio total ativo.

## Uso

Abra o **PowerShell como Administrador** na pasta do script.

Ensaio, sem alterar nada — mostra a instalação detectada e o que seria feito:

```powershell
powershell -ExecutionPolicy Bypass -File .\Block-NXInternet.ps1 -WhatIfOnly
```

Aplicar o bloqueio:

```powershell
powershell -ExecutionPolicy Bypass -File .\Block-NXInternet.ps1
```

Reverter tudo:

```powershell
powershell -ExecutionPolicy Bypass -File .\Block-NXInternet.ps1 -Undo
```

## Parâmetros

| Parâmetro | Efeito |
|---|---|
| `-WhatIfOnly` | Mostra o que seria feito, sem criar nenhuma regra. |
| `-Undo` | Remove todas as regras criadas pelo script. |
| `-CoreOnly` | Bloqueia só os executáveis principais (inclui update manager e telemetria), em vez de todos os `.exe`. Bem menos regras. |
| `-NxPath "D:\..."` | Força o caminho da instalação, caso a detecção automática falhe. |
| `-AllowLan` | Mantém a rede local liberada, bloqueando apenas a internet pública. Necessário só se a licença passar a vir de um servidor de rede (FlexLM/SPLM). |
| `-Force` | Pula a confirmação quando o número de regras for grande. |

## Como a instalação é detectada

Em ordem, até encontrar:

1. Variáveis de ambiente `UGII_BASE_DIR` / `UGII_ROOT_DIR`
2. Chaves de desinstalação do registro (`DisplayName` casando com NX / Siemens NX / Unigraphics)
3. Chaves próprias da Siemens no registro
4. Pastas padrão (`Program Files\Siemens\NX*`, `Program Files (x86)\Siemens\NX*`, `\Siemens\NX*`, `Program Files\UGS`) em **todos** os discos
5. O processo `ugraf.exe`, se estiver rodando

Caminhos apontando para `NXBIN` ou `UGII` são normalizados para a raiz da versão.

## Regras criadas

Todas ficam no grupo **`Bloqueio Internet - Siemens NX`**, o que torna a remoção atômica.

Conferir na interface: `wf.msc` → Regras de Saída → ordenar por Grupo.

Conferir no PowerShell:

```powershell
Get-NetFirewallRule -Group 'Bloqueio Internet - Siemens NX' | Measure-Object
```

No modo `-AllowLan`, o bloqueio cobre a internet pública via o complemento dos ranges
privados em IPv4 (tudo que não é `10/8`, `127/8`, `169.254/16`, `172.16-31/12`,
`192.168/16`) e `2000::/3` em IPv6 (espaço global unicast roteável).

## Limitações

- O bloqueio é **por executável**. Um componente Siemens instalado *fora* da pasta do NX
  que acesse a rede em nome dele não é coberto — rode com `-WhatIfOnly` para ver a lista exata.
- Regras de firewall não têm efeito com o Firewall do Windows desligado. O script detecta
  e avisa se algum perfil estiver desativado.
- Exige privilégios de Administrador.
