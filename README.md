# fuzzy

idee:
- lo stesso programma deve essere eseguito contemporaneamente N volte (processo = subprocess.Popen([nome_eseguibile]))
- potenzialmente ogni richiesta di input del programma potrebbe essere vulnerabile, come testarle tutte? alcune potrebbero essere raggiungibili solo un una certa "ramificazione" da seguire"
- vari tipi di input devono essere mandati ad OGNI richiesta di input. Iniziano ad essere parecchie
- gdb permette di skippare direttamente agli input??
- quanti tipi di response esistono? magari il problema rimane semplicemente in "hang on". Come classificarli?
- mettere statististiche come il tempo di esecuzione per ogni run
- se il programma continuare a richiedere input, mettere un limite superiore

# TO DO
# - thread su ogni lista di payloads: fatto
# - for su avvio di thread per ogni lista di payloads: fatto
# - gestire e classificare ogni crash/errore del processo
# - problema domande booleane: ramificazione degli input (ovvero cosa fare quando ho una risposta booleana e in base alla scelta c'è un altro set di domande)
# da fare con prodotto cartesiano dei payloads
