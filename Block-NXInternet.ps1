<#
.SYNOPSIS
    Bloqueia o acesso a internet do Siemens NX via Firewall do Windows Defender.

.DESCRIPTION
    Localiza a instalacao do Siemens NX, enumera os executaveis e cria regras de
    firewall de SAIDA (outbound) bloqueando o trafego para a internet publica.

    Por padrao bloqueia TODO o trafego de saida (licenca local / nodelocked,
    portanto nao ha servidor de licenca em rede a preservar). Use -AllowLan
    se algum dia precisar liberar a rede local.

    Trafego de loopback (127.0.0.1) nao e filtrado pelo Firewall do Windows,
    entao licenciamento local continua funcionando normalmente.

    Todas as regras sao criadas no grupo "Bloqueio Internet - Siemens NX",
    o que permite remove-las de uma vez (veja -Undo).

.PARAMETER NxPath
    Caminho da instalacao do NX. Se omitido, o script tenta detectar sozinho.

.PARAMETER CoreOnly
    Bloqueia apenas os executaveis principais conhecidos, em vez de todos os .exe.

.PARAMETER AllowLan
    Mantem a rede local (LAN) liberada, bloqueando apenas a internet publica.
    Necessario apenas se a licenca passar a vir de um servidor de rede.

.PARAMETER Undo
    Remove todas as regras criadas por este script.

.PARAMETER Force
    Pula a confirmacao quando o numero de regras for grande.

.PARAMETER WhatIfOnly
    Apenas mostra o que seria feito, sem criar nenhuma regra.

.EXAMPLE
    .\Block-NXInternet.ps1
.EXAMPLE
    .\Block-NXInternet.ps1 -WhatIfOnly
.EXAMPLE
    .\Block-NXInternet.ps1 -NxPath "D:\Siemens\NX2412"
.EXAMPLE
    .\Block-NXInternet.ps1 -AllowLan
.EXAMPLE
    .\Block-NXInternet.ps1 -Undo
#>

[CmdletBinding()]
param(
    [string] $NxPath,
    [switch] $CoreOnly,
    [switch] $AllowLan,
    [switch] $Undo,
    [switch] $Force,
    [switch] $WhatIfOnly
)

$ErrorActionPreference = 'Stop'
$GroupName = 'Bloqueio Internet - Siemens NX'

# ---------------------------------------------------------------- privilegios
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  ERRO: este script precisa ser executado como Administrador." -ForegroundColor Red
    Write-Host "  Feche esta janela, clique com o botao direito no PowerShell" -ForegroundColor Yellow
    Write-Host "  e escolha 'Executar como administrador'." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# ------------------------------------------------------------------- undo
if ($Undo) {
    $existing = Get-NetFirewallRule -Group $GroupName -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Host "Nenhuma regra do grupo '$GroupName' encontrada. Nada a remover." -ForegroundColor Yellow
        exit 0
    }
    Write-Host "Removendo $($existing.Count) regra(s)..." -ForegroundColor Cyan
    $existing | Remove-NetFirewallRule
    Write-Host "Regras removidas. O Siemens NX voltou a ter acesso a internet." -ForegroundColor Green
    exit 0
}

# -------------------------------------------------------- detectar instalacao
function Find-NxInstall {
    $candidates = New-Object System.Collections.Generic.List[string]

    # 1) variaveis de ambiente definidas pelo proprio NX
    foreach ($v in 'UGII_BASE_DIR','UGII_ROOT_DIR') {
        $val = [Environment]::GetEnvironmentVariable($v, 'Machine')
        if (-not $val) { $val = [Environment]::GetEnvironmentVariable($v, 'Process') }
        if ($val -and (Test-Path $val)) { $candidates.Add($val) }
    }

    # 2) chaves de desinstalacao do registro
    $unins = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($u in $unins) {
        Get-ItemProperty $u -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match '(?i)\bNX\b|Siemens\s*NX|Unigraphics' -and $_.InstallLocation } |
            ForEach-Object { if (Test-Path $_.InstallLocation) { $candidates.Add($_.InstallLocation) } }
    }

    # 3) chaves proprias da Siemens
    foreach ($k in 'HKLM:\SOFTWARE\Siemens','HKLM:\SOFTWARE\WOW6432Node\Siemens','HKLM:\SOFTWARE\Unigraphics Solutions') {
        if (Test-Path $k) {
            Get-ChildItem $k -Recurse -Depth 2 -ErrorAction SilentlyContinue | ForEach-Object {
                $p = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue)
                foreach ($n in 'InstallLocation','InstallPath','Path','UGII_BASE_DIR') {
                    if ($p.$n -and (Test-Path $p.$n)) { $candidates.Add($p.$n) }
                }
            }
        }
    }

    # 4) varredura das pastas padrao
    $roots = @()
    foreach ($d in (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null })) {
        $roots += @(
            (Join-Path $d.Root 'Program Files\Siemens'),
            (Join-Path $d.Root 'Program Files (x86)\Siemens'),
            (Join-Path $d.Root 'Siemens'),
            (Join-Path $d.Root 'Program Files\UGS'),
            (Join-Path $d.Root 'apps\Siemens')
        )
    }
    foreach ($r in $roots) {
        if (Test-Path $r) {
            Get-ChildItem $r -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)^NX' } |
                ForEach-Object { $candidates.Add($_.FullName) }
        }
    }

    # 5) processo do NX rodando agora
    Get-Process -Name ugraf -ErrorAction SilentlyContinue | ForEach-Object {
        try { $candidates.Add((Split-Path (Split-Path $_.Path -Parent) -Parent)) } catch {}
    }

    # normaliza: sobe para a raiz da versao se apontou para NXBIN/UGII
    $clean = New-Object System.Collections.Generic.List[string]
    foreach ($c in $candidates) {
        $p = $c.TrimEnd('\')
        if ($p -match '(?i)\\(NXBIN|UGII)$') { $p = Split-Path $p -Parent }
        if (Test-Path $p) { $clean.Add((Resolve-Path $p).Path) }
    }
    return ($clean | Sort-Object -Unique)
}

if ($NxPath) {
    if (-not (Test-Path $NxPath)) { Write-Host "ERRO: caminho nao encontrado: $NxPath" -ForegroundColor Red; exit 1 }
    $installs = @((Resolve-Path $NxPath).Path)
} else {
    Write-Host "Procurando a instalacao do Siemens NX..." -ForegroundColor Cyan
    $installs = @(Find-NxInstall)
}

if (-not $installs -or $installs.Count -eq 0) {
    Write-Host ""
    Write-Host "  Nao consegui localizar o Siemens NX automaticamente." -ForegroundColor Red
    Write-Host "  Rode novamente informando o caminho, por exemplo:" -ForegroundColor Yellow
    Write-Host '     .\Block-NXInternet.ps1 -NxPath "C:\Program Files\Siemens\NX2412"' -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "Instalacao(oes) encontrada(s):" -ForegroundColor Green
$installs | ForEach-Object { Write-Host "   $_" }

# ------------------------------------------------------- coletar executaveis
$coreNames = @(
    'ugraf.exe','ugmanager.exe','nx.exe','nxopen.exe','ugii.exe',
    'lmgrd.exe','ugslmd.exe','splm_lmgrd.exe','SPLMLicenseServer.exe',
    'nxlicensing.exe','licensing.exe','LicenseUtility.exe',
    'NXUpdateManager.exe','UpdateManager.exe','SiemensUpdate.exe',
    'CustomerExperience.exe','ceip.exe','nxwebbrowser.exe','WebBrowser.exe',
    'HelpViewer.exe','nxhelp.exe','SiemensNXWeb.exe','curl.exe','wget.exe',
    'java.exe','javaw.exe','jre.exe','python.exe','pythonw.exe','node.exe'
)

$exes = New-Object System.Collections.Generic.List[string]
foreach ($root in $installs) {
    if ($CoreOnly) {
        Get-ChildItem -Path $root -Recurse -File -Filter *.exe -ErrorAction SilentlyContinue |
            Where-Object { $coreNames -contains $_.Name } |
            ForEach-Object { $exes.Add($_.FullName) }
    } else {
        Get-ChildItem -Path $root -Recurse -File -Filter *.exe -ErrorAction SilentlyContinue |
            ForEach-Object { $exes.Add($_.FullName) }
    }
}
$exes = @($exes | Sort-Object -Unique)

if ($exes.Count -eq 0) {
    Write-Host "Nenhum executavel encontrado nas pastas acima." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Executaveis a bloquear: $($exes.Count)" -ForegroundColor Green
if ($exes.Count -gt 15) {
    $exes | Select-Object -First 10 | ForEach-Object { Write-Host "   $_" -ForegroundColor DarkGray }
    Write-Host "   ... e mais $($exes.Count - 10)" -ForegroundColor DarkGray
} else {
    $exes | ForEach-Object { Write-Host "   $_" -ForegroundColor DarkGray }
}

# --------------------------------------------------------------- alvo de rede
# Complemento dos ranges privados: tudo que NAO e 10/8, 127/8, 169.254/16,
# 172.16-31/12 e 192.168/16. Assim a LAN e o servidor de licenca continuam OK.
$publicV4 = @(
    '0.0.0.0-9.255.255.255',
    '11.0.0.0-126.255.255.255',
    '128.0.0.0-169.253.255.255',
    '169.255.0.0-172.15.255.255',
    '172.32.0.0-192.167.255.255',
    '192.169.0.0-255.255.255.255'
)
$publicV6 = @('2000::/3')   # espaco global unicast roteavel na internet

if ($AllowLan) {
    $targets = @(
        @{ Suffix='IPv4'; Addr=$publicV4; Desc='internet publica IPv4' },
        @{ Suffix='IPv6'; Addr=$publicV6; Desc='internet publica IPv6' }
    )
    Write-Host ""
    Write-Host "MODO: bloqueia internet publica, rede local (LAN) liberada." -ForegroundColor Cyan
} else {
    $targets = @( @{ Suffix='ALL'; Addr='Any'; Desc='todo trafego de saida' } )
    Write-Host ""
    Write-Host "MODO: bloqueio TOTAL de saida (licenca local, nada a preservar)." -ForegroundColor Cyan
    Write-Host "      Loopback (127.0.0.1) nao e filtrado pelo firewall - licenca local OK." -ForegroundColor DarkGray
}

$totalRules = $exes.Count * $targets.Count
Write-Host ""
Write-Host "Serao criadas $totalRules regra(s) de firewall no grupo '$GroupName'." -ForegroundColor Cyan

# perfis de firewall desligados tornam as regras inertes
$off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled })
if ($off.Count -gt 0) {
    Write-Host ""
    Write-Host "  AVISO: o Firewall do Windows esta DESLIGADO no(s) perfil(is): $($off.Name -join ', ')" -ForegroundColor Yellow
    Write-Host "         As regras serao criadas, mas so terao efeito com o firewall ligado." -ForegroundColor Yellow
    Write-Host "         Para ligar:  Set-NetFirewallProfile -Profile $($off.Name -join ',') -Enabled True" -ForegroundColor Yellow
}

if ($WhatIfOnly) {
    Write-Host ""
    Write-Host "-WhatIfOnly ativo: nada foi alterado." -ForegroundColor Yellow
    exit 0
}

if ($totalRules -gt 400 -and -not $Force) {
    Write-Host ""
    Write-Host "  Isso e um volume grande de regras e pode levar alguns minutos." -ForegroundColor Yellow
    Write-Host "  Alternativa mais enxuta: rode com -CoreOnly (so os executaveis principais)." -ForegroundColor Yellow
    $ans = Read-Host "  Continuar mesmo assim? (S/N)"
    if ($ans -notmatch '^(?i)s') { Write-Host "Cancelado. Nada foi alterado." -ForegroundColor Yellow; exit 0 }
}

# --------------------------------------------------- limpar regras anteriores
$old = Get-NetFirewallRule -Group $GroupName -ErrorAction SilentlyContinue
if ($old) {
    Write-Host "Removendo $($old.Count) regra(s) anterior(es) deste script..." -ForegroundColor DarkGray
    $old | Remove-NetFirewallRule
}

# ------------------------------------------------------------- criar regras
Write-Host ""
$i = 0; $created = 0; $failed = 0
foreach ($exe in $exes) {
    $name = [IO.Path]::GetFileNameWithoutExtension($exe)
    foreach ($t in $targets) {
        $i++
        Write-Progress -Activity "Criando regras de firewall" `
                       -Status "$i / $totalRules - $name" `
                       -PercentComplete ([int](100 * $i / $totalRules))
        $ruleName = "Bloq NX Internet [{0:D4}] - {1} ({2})" -f $i, $name, $t.Suffix
        try {
            New-NetFirewallRule `
                -DisplayName  $ruleName `
                -Group        $GroupName `
                -Description  "Bloqueia $($t.Desc) para $exe" `
                -Direction    Outbound `
                -Action       Block `
                -Program      $exe `
                -RemoteAddress $t.Addr `
                -Profile      Any `
                -Enabled      True | Out-Null
            $created++
        } catch {
            $failed++
            Write-Host "   Falhou: $exe [$($t.Suffix)] -> $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }
}
Write-Progress -Activity "Criando regras de firewall" -Completed

# ------------------------------------------------------------------ resultado
Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host " CONCLUIDO" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host " Regras criadas : $created"
if ($failed -gt 0) { Write-Host " Falhas         : $failed" -ForegroundColor Yellow }
Write-Host " Grupo          : $GroupName"
Write-Host ""
Write-Host " Conferir no Firewall do Windows:" -ForegroundColor Cyan
Write-Host "   wf.msc  ->  Regras de Saida  ->  ordenar por Grupo"
Write-Host ""
Write-Host " Listar via PowerShell:" -ForegroundColor Cyan
Write-Host "   Get-NetFirewallRule -Group '$GroupName' | Measure-Object"
Write-Host ""
Write-Host " Para DESFAZER tudo:" -ForegroundColor Cyan
Write-Host "   .\Block-NXInternet.ps1 -Undo"
Write-Host ""
