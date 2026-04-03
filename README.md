# volatility3-use
Guia prático de análise de memória com Volatility 3 para DFIR.

---

## ⚙️ Instalação de dependências

```powershell
py -3.12 -m pip install -U volatility3
py -3.12 -m pip install pycryptodome
py -3.12 -m pip install yara-python
```

> Se algum `.txt` gerado tiver 0kb, o plugin não rodou. Verifique no terminal — provavelmente falta uma dependência acima.

---

## 🔧 Variáveis de ambiente

```powershell
$Mem = "nome_do_arquivo.mem"; $Out = "NOME_DA_PASTA_SAIDA"; mkdir $Out -Force | Out-Null
```

---

## 🚀 Script de extração principal

```powershell
$plugins = @(
  "windows.info.Info","windows.shimcachemem.ShimcacheMem","windows.netscan.NetScan",
  "windows.netstat.NetStat","windows.pstree.PsTree","windows.cmdline.CmdLine",
  "windows.envars.Envars","windows.privileges.Privs","windows.getsids.GetSIDs",
  "windows.svcscan.SvcScan","windows.getservicesids.GetServiceSIDs",
  "windows.malware.malfind.Malfind","windows.callbacks.Callbacks","windows.dlllist.DllList",
  "windows.symlinkscan.SymlinkScan","windows.sessions.Sessions","windows.modules.Modules",
  "windows.truecrypt.Passphrase","windows.modscan.ModScan","windows.registry.hivelist.HiveList",
  "windows.hashdump.Hashdump","windows.lsadump.Lsadump","windows.registry.amcache.Amcache",
  "windows.ssdt.SSDT","windows.driverirp.DriverIrp","windows.ldrmodules.LdrModules",
  "windows.bigpools.BigPools","windows.desktops.Desktops",
  "windows.skeleton_key_check.Skeleton_Key_Check","windows.joblinks.JobLinks",
  "windows.verinfo.VerInfo","windows.filescan.FileScan","windows.mbrscan.MBRScan",
  "windows.mutantscan.MutantScan","timeliner.Timeliner","windows.psscan.PsScan",
  "windows.handles.Handles","windows.orphan_kernel_threads.Threads","windows.psxview.PsXView",
  "windows.deskscan.DeskScan","windows.devicetree.DeviceTree","windows.malware.svcdiff.SvcDiff",
  "windows.malware.pebmasquerade.PebMasquerade"
)
foreach ($p in $plugins) {
  $nome = $p -replace "[\\.]","_"
  Write-Host "Rodando $p..."
  py -3.12 vol.py -f $Mem $p | Out-File "$Out\$nome.txt" -Encoding UTF8
}
```

---

## ⏳ Script demorado (rodar depois do principal)

Estes plugins demoram muito — rodar separado após o principal terminar.

```powershell
$plugins = @(
  "windows.hollowprocesses.HollowProcesses","windows.vadinfo.VadInfo",
  "windows.registry.printkey.PrintKey","windows.mftscan.MFTScan",
  "windows.registry.certificates.Certificates","windows.registry.userassist.UserAssist"
)
foreach ($p in $plugins) {
  $nome = $p -replace "[\\.]","_"
  Write-Host "Rodando $p..."
  py -3.12 vol.py -f $Mem $p | Out-File "$Out\$nome.txt" -Encoding UTF8
}
```

---

## 🔍 Aprofundamento — YARA

Busca por string, padrão ou regra YARA direto nas regiões de memória dos processos. Útil para caçar malware conhecido, RATs, ferramentas de acesso remoto e shellcode.

**Sintaxe base:**

```powershell
py -3.12 vol.py -f $Mem windows.vadyarascan.VadYaraScan --yara-string "TERMO" | Out-File "$Out\yara_TERMO.txt" -Encoding UTF8
```

**Exemplos de uso real:**

| O que caçar | String sugerida |
|---|---|
| Ferramentas de acesso remoto (RAT/RMM) | `"ScreenConnect"`, `"AnyDesk"`, `"TeamViewer"`, `"Atera"` |
| Frameworks de C2 | `"Cobalt Strike"`, `"Metasploit"`, `"Sliver"`, `"Havoc"` |
| Credenciais em memória | `"password"`, `"passwd"`, `"Authorization"` |
| Comandos suspeitos | `"powershell -enc"`, `"cmd /c"`, `"certutil"`, `"bitsadmin"` |
| Persistência | `"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"` |
| Injeção/shellcode | `"VirtualAlloc"`, `"CreateRemoteThread"` |
| Ransomware | `"YOUR FILES"`, `"decrypt"`, `"bitcoin"` |

**Usando arquivo de regras YARA** (mais poderoso):

```powershell
# Gerar all_clean.yar filtrando regras incompatíveis com Volatility
py -3.12 -c "
import yara, glob, os

yara_dir = r'D:\volatility3\signature-base\yara'
output = r'D:\volatility3\all_clean.yar'
skipped = []
rules = []

for f in glob.glob(yara_dir + r'\*.yar'):
    try:
        yara.compile(f)
        rules.append(open(f, 'r', encoding='utf-8', errors='ignore').read())
    except Exception as e:
        skipped.append(os.path.basename(f))

with open(output, 'w', encoding='ascii', errors='ignore') as out:
    for r in rules:
        out.write(r)
        out.write('\n')

print('Skipped:', skipped)
print(f'Clean rules: {len(rules)}')
"

# Rodar scan com o arquivo gerado
py -3.12 vol.py -f $Mem windows.vadyarascan.VadYaraScan --yara-file "all_clean.yar" | Out-File "$Out\yara_full_scan.txt" -Encoding UTF8
```

> 💡 Regras prontas: [YARA Rules no GitHub](https://github.com/Yara-Rules/rules) | [signature-base (Nextron)](https://github.com/Neo23x0/signature-base) | [Awesome YARA](https://github.com/InQuest/awesome-yara)

**YARA direcionado por IOC (mais eficiente):**

```powershell
# Strings de IOCs conhecidos (ex: ScreenConnect CVE-2024-1708/1709)
py -3.12 vol.py -f $Mem windows.vadyarascan.VadYaraScan --yara-string "ScreenConnect|LB3.exe|msappdata.msi|RunSchedulerTaskOnce.ps1|update.dat|spsrv.exe" | Out-File "$Out\yara_screenconnect.txt"

# Paths suspeitos
py -3.12 vol.py -f $Mem windows.vadyarascan.VadYaraScan --yara-string "C:\\Windows\\TEMP\\ScreenConnect|C:\\perflogs\\RunSchedulerTaskOnce.ps1|C:\\programdata\\update.dat" | Out-File "$Out\yara_paths.txt"
```

---

## 🧲 Procdump — extração de executável da memória

⚠️ **Apenas com permissão da gestão e em ambiente isolado**

**1. Obter o PID do processo suspeito:**

```powershell
cat "$Out\windows_pstree_PsTree.txt" | Select-String "nomedoprocesso"
```

**2. Criar pasta de output:**

```powershell
mkdir "$Out\procdump" -Force | Out-Null
```

**3. Rodar o dump:**

```powershell
py -3.12 vol.py -f $Mem --pid 1234 --dump -o "$Out\procdump" windows.pslist
```

**4. Dump de vários PIDs de uma vez:**

```powershell
$pids = @(1234, 5678, 9012)
foreach ($pid in $pids) {
  Write-Host "Dumpando PID $pid..."
  py -3.12 vol.py -f $Mem --pid $pid --dump -o "$Out\procdump" windows.pslist
}
```

**5. O Volatility gera arquivos tipo `pid.1234.0x400000.dmp`. Próximos passos:**

```powershell
# Calcular hash de todos os dumps
Get-FileHash "$Out\procdump\*.exe" -Algorithm SHA256 | Out-File "$Out\procdump\hashes.txt"

# YARA local nos dumps (não precisa de Volatility)
Get-ChildItem "$Out\procdump\*.exe" | ForEach-Object {
  yara "D:\volatility3\signature-base\yara\apt_*.yar" $_.FullName
}
```

- Abrir no DIE, PE Studio, IDA, etc.
- Subir no VirusTotal (se houver permissão da gestão)

---

## 📖 Descrição dos plugins

| Plugin | Descrição |
|---|---|
| `windows.info.Info` | Metadados do dump: versão do SO, arquitetura, KDBG, DTB, horário de boot. |
| `windows.shimcachemem.ShimcacheMem` | Lê entradas do Shimcache na árvore AVL do ahcache.sys. Programas executados com path e timestamp. |
| `windows.pstree.PsTree` | Árvore hierárquica pai→filho dos processos. Identifica parentesco anômalo. |
| `windows.psscan.PsScan` | Varre memória física por pool tags. Encontra processos terminados e ocultos. |
| `windows.psxview.PsXView` | Cruza listas de processos de várias fontes para detectar processos ocultos por rootkits. |
| `windows.cmdline.CmdLine` | Linha de comando completa usada para iniciar cada processo com todos os argumentos. |
| `windows.envars.Envars` | Variáveis de ambiente de cada processo (PATH, TEMP, USERNAME, COMPUTERNAME). |
| `windows.privileges.Privs` | Privilégios de token de cada processo e se estão habilitados ou não. |
| `windows.getsids.GetSIDs` | SIDs de segurança de cada processo. Mostra sob qual conta ele roda. |
| `windows.handles.Handles` | Todos os handles abertos por processo: arquivos, registry, mutexes, semáforos, threads. |
| `windows.netscan.NetScan` | Pool scanning por conexões TCP/UDP. Pega ativas, encerradas e residuais com PID. |
| `windows.netstat.NetStat` | Conexões ativas e portas em escuta no momento exato do dump. |
| `windows.hollowprocesses.HollowProcesses` | Compara imagem em disco vs memória. Divergência indica process hollowing. |
| `windows.svcscan.SvcScan` | Serviços do Windows: nome, estado, tipo, conta de execução, path do binário. |
| `windows.getservicesids.GetServiceSIDs` | SIDs gerados para cada serviço. Mapeia a identidade de segurança assumida. |
| `windows.ldrmodules.LdrModules` | Cruza 3 listas do PEB (InLoad, InInit, InMem). False em alguma = DLL oculta. |
| `windows.modules.Modules` | Drivers e módulos carregados no kernel (ring 0). |
| `windows.modscan.ModScan` | Pool scanning por módulos do kernel. Pega drivers descarregados ou removidos da lista. |
| `windows.filescan.FileScan` | Varre memória por FILE_OBJECTs. Lista todos os arquivos referenciados, inclusive deletados. |
| `windows.mftscan.MFTScan` | Entradas da MFT do NTFS na memória. Timestamps MAC, nomes, metadados. |
| `windows.registry.hivelist.HiveList` | Hives do registro em memória (SAM, SYSTEM, SOFTWARE, NTUSER.DAT) com offsets. |
| `windows.registry.amcache.Amcache` | Programas executados: hash SHA-1, timestamp de primeira execução e metadata do PE. |
| `windows.hashdump.Hashdump` | Extrai hashes NTLM do hive SAM. Formato usuario:RID:LM:NTLM. |
| `windows.lsadump.Lsadump` | Segredos do LSA: senhas de serviços, chaves de autenticação, segredos de domínio. |
| `windows.cachedump.Cachedump` | Credenciais de domínio cacheadas (DCC2). Hashes de logins guardados localmente. |
| `windows.ssdt.SSDT` | System Service Descriptor Table. Hooks indicam rootkit interceptando syscalls. |
| `windows.driverirp.DriverIrp` | Funções IRP de cada driver. Hooks em IRP_MJ_* indicam rootkit filtrando I/O. |
| `windows.devicetree.DeviceTree` | Árvore de drivers e dispositivos. Identifica device stacking malicioso. |
| `windows.desktops.Desktops` | Desktops e window stations. Processos em desktops alternativos podem estar ocultos. |
| `windows.deskscan.DeskScan` | Scans por instâncias de Desktop de cada Window Station. |
| `windows.mutantscan.MutantScan` | Objetos Mutex/Mutant na memória. Nomes de mutex são IOCs clássicos de malware. |
| `windows.bigpools.BigPools` | Large pool allocations do kernel. Identifica componentes com alocações grandes. |
| `windows.mbrscan.MBRScan` | Escaneia MBRs na memória. Detecta bootkits com persistência pré-boot. |
| `windows.skeleton_key_check.Skeleton_Key_Check` | Verifica presença do ataque Skeleton Key (backdoor Kerberos) no LSASS. |
| `windows.joblinks.JobLinks` | Job Objects e processos agrupados. Malware usa Jobs para controlar processos filhos. |
| `windows.verinfo.VerInfo` | Version Info dos PEs: produto, empresa, versão. Identifica binários mascarados. |
| `windows.orphan_kernel_threads.Threads` | Threads do kernel sem módulo dono. Sem driver associado = rootkit. |
| `windows.malware.svcdiff.SvcDiff` | Compara serviços por list walking vs scanning. Divergência indica rootkit. |
| `windows.malware.pebmasquerade.PebMasquerade` | Detecta spoofing de nome de processo comparando EPROCESS e PEB. |
| `windows.registry.certificates.Certificates` | Certificados digitais no registro. Identifica CAs raiz maliciosas instaladas. |
| `windows.vadinfo.VadInfo` | Virtual Address Descriptors detalhados: permissões, proteções, tipo de região por processo. |
| `timeliner.Timeliner` | Timeline unificada de todos os artefatos com timestamp. |
| `windows.malware.malfind.Malfind` | Lista regiões de memória com código potencialmente injetado: permissão RWX, sem módulo mapeado, padrão de shellcode. |
| `windows.callbacks.Callbacks` | Callbacks registrados no kernel. Rootkits registram callbacks para interceptar eventos do sistema. |
| `windows.dlllist.DllList` | DLLs carregadas por processo com path completo e base address. |
| `windows.symlinkscan.SymlinkScan` | Objetos de symbolic link do Object Manager. Detecta device aliasing malicioso. |
| `windows.sessions.Sessions` | Sessões de logon vinculadas a cada processo. Session 0 = serviço, 1+ = interativo. |
| `windows.registry.userassist.UserAssist` | Decodifica UserAssist (ROT13). Programas executados via Explorer com contagem e timestamp. |
| `windows.truecrypt.Passphrase` | Detecta volumes TrueCrypt/VeraCrypt montados e extrai metadados. |
| `windows.strings.Strings` | Correlaciona strings da memória com o processo dono e endereço correspondente. |
| `windows.vadyarascan.VadYaraScan` | Roda regras YARA direto contra as regiões VAD dos processos. Caça padrões de malware e shellcode. |
