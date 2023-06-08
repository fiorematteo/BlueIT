
# SOC Automation

Nel seguente documento viene spiegato come modificare vari parametri nel file di config del programma SOC Automation.  
Ricordarsi della sintassi dei file JSON, fallire in questo può causare gravi danni.  
Ricordarsi inoltre che qualunque valore è case sensitive.

I titoli delle seguenti sezioni corrispondono alle varie sezioni presenti nel file **config.json** e sono anche nello
stesso ordine.  
L'unica eccezione è il titolo *Connessioni a vari API* che non è presente nel file di configurazione, ma è presente in 
questo file per questioni di leggibilità.

*Per maggior leggibilità nel file è possibile andare a capo dopo ogni apertura di parentesi e ogni virgola.*

## SOC_Automation
Per cambiare il numero di secondi tra un controllo e il successivo bisogna cambiare il valore associato al campo
`"seconds_of_sleep"` con il numero di secondi che si vuole.

## MSTeams
Per cambiare il canale su cui il programma manda le notifiche bisogna prima creare un nuovo webhook sul nuovo canale e poi
sostituire il vecchio webhook associato al campo `"connectorcard"` con il nuovo webhook.

## QRadar

Per modificare il valore massimo di severity per cui il bot assegna utenti alle offensive basta modificare il valore
associato al campo `"severity"` con il nuovo valore massimo.  
Se il valore è 8 per esempio nel caso una offensiva sia di severity 8 non verrà assegnata a nessuno.

Per cambiare l'ip associato a QRadar bisogna andare nel campo `"server_url"` e modificare l'ip.

Per modificare la lista delle persone a cui assegnare le varie offensive bisogna modificare la lista del campo `"user_list"`.

Per aggiungere use case alla lista delle use case di cui bisogna analizzare l'url (***DEVE*** comparire nel campo offense
source) bisogna aggiungere il campo `Descrizione` (presente nella pagina delle offensive di QRadar) seguito da `\n`
(es: `"Descrizione\n"`) alla lista `"descriptions_list"` presente nella sezione `"analyze_url"`.

Per aggiungere use case alla lista delle use case di cui bisogna analizzare l'ip (***DEVE*** comparire nel campo offense
source) bisogna aggiungere il campo `Descrizione` (presente nella pagina delle offensive di QRadar) seguito da `\n`
(es: `"Descrizione\n"`) alla lista `"descriptions_list"` presente nella sezione `"analyze_ip"`.

Per aggiungere use case alla lista di note semplici bisogna seguire il seguente format:  
`"Descrizione\n": "Nota da mettere"`  
Per *Descrizione* si intende il campo `Descrizione` (presente nella pagina delle offensive di QRadar).  
Nel caso si voglia far comparire il campo `offense source` (presente nella pagina delle offensive di QRadar) 
dell'offensiva relativa basta mettere `%offense_source%` nella nota dove si vuole far comparire il campo.

Per aggiungere una nota relativa agli IIS bisogna seguire il seguente format:  
`"Descrizione\n": "Nota da mettere"`  
Per *Descrizione* si intende ilo campo `Descrizione` (presente nella pagina delle offensive di QRadar).  
Nel caso si voglia far comparire il campo `offense source` (presente nella pagina delle offensive di QRadar) 
dell'offensiva relativa basta mettere `%offense_source%` nella nota dove si vuole far comparire il campo.  
Nel caso si voglia far comparire il sito effettivo dell'offensiva relativa basta mettere `%IIS_web_site%` nella nota 
dove si vuole far comparire il campo.

Per aggiungere un nuovo web server IIS bisogna aggiungere al campo `"IIS_dict"` una nuova chiave, il cui nome deve essere
uguale al nome del web server al cui interno devono esserci delle coppie di chiave - valore che corrispondono rispettivamente
al codice univoco del sito e il sito.  
Format:  
`"nome web server": {`  
`"W3SVC1": "Default Web Site",`  
`"W3SVC2": "Nome sito 1"`  
`}`  
Esempio:  
`"W16ARAPP01-IIS": {`  
`"W3SVC1": "Default Web Site",`  
`"W3SVC2": "api-evodent.dentalpro.it"`  
`}`  

Per aggiungere un nuovo sito IIS bisogna aggiungere al campo corrispondente al nome del relativo web server, nel campo
`"IIS_dict"`, il codice univoco e il nome del sito.  
Format:  
`"W3SVC1": "Default Web Site"`

Per aggiungere una lista d'ip da aggiungere a QRAdar bisogna aggiungere, nel campo `"txt_ip_list"`, un nome per la lista
a cui è associato il nome del set (o serie) della lista e l'url da cui scaricare la lista.  
Format:  
`"Nome lista": {`  
`"set_name": "Nome del set",`  
`"url": "url della lista"`  
`}`  
Esempio:  
`"FireHOL_list_1": {`  
`"set_name": "FireHOL_level_1",`  
`"url": "https://iplists.firehol.org/files/firehol_level1.netset"`  
`}`  
Il nome della lista non importa veramente.

## Connessioni a vari API

È possibile disattivare l'analisi di qualunque servizio api cambiando il valore associato al campo `"in_use"` da `true` a
`false`.

### UrlScan

Per modificare l'url bisogna sostituire il valore associato al campo `"url"` con la nuova url.  
Per modificare la chiave api bisogna cambiare valore associato al campo `"API-Key"`, presente nel campo `"headers"`.

### VirusTotal

Per modificare l'url bisogna sostituire il valore associato al campo `"url"` con la nuova url.  
Per modificare la chiave api bisogna cambiare valore associato al campo `"x-apikey"`, presente nei campi `"headers_x_post"`
e `"headers_x_get"`.

### AbuseIp

Per modificare l'url bisogna sostituire il valore associato al campo `"url"` con la nuova url.  
Per modificare la chiave api bisogna cambiare valore associato al campo `"Key"`, presente nel campo `"headers"`.

### Pulsedive

Per modificare l'url bisogna sostituire il valore associato al campo `"url"` con la nuova url.  
Per modificare la chiave api bisogna cambiare valore associato al campo `"Key"`, presente nei campi `"post_params"`
e `"get_params"`.

### CriminalIp

Per modificare l'url bisogna sostituire il valore associato al campo `"url"` con la nuova url.  
Per modificare la chiave api bisogna cambiare valore associato al campo `"x-api-key"`, presente nel campo `"headers"`.

### Google_Safe_Browsing
Per modificare la chiave api bisogna cambiare valore associato al campo `"key"`.

### AlienVault

Per modificare l'url bisogna sostituire il valore associato al campo `"url_x_ip"` o `"url_x_url"` con la nuova url.  
Per modificare la chiave api bisogna cambiare valore associato al campo `"X-OTX-API-KEY"`, presente nel campo `"headers"`.

### IpRegistry

Per modificare l'url bisogna sostituire il valore associato al campo `"url"` con la nuova url.  
Per modificare la chiave api bisogna cambiare valore associato al campo `"key"`.
