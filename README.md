# Segurança da Informação

1. O que é Dado?
    - Dado pode ser uma representação simbólica, numérica ou textual qualquer.
    Ex:(25, Python, @)
2. O que é Informação?
    - Informação é o conjunto ou a junção de dados que fazem um contexto ou sentido.
    Ex:(João tem 25 anos, Python é uma linguagem de programação, O email de joão é joão_25@python.com)
3. O que é Segurança da Informação?
    - Área que tem como objetivo assegurar que todos os dados de uma ou mais informações estejam sempre confidenciais, íntegros e disponíveis em qualquer meio de comunicação.
4. Porque Segurança?
    - O ser humano tem necessidade de segurança!
        1. Fisiológicas
        2. Segurança
        3. Sociais
        4. Estima
        5. Auto Realização
5. Princípios da Segurança da Informação?
    - Integridade
        - Princípio que visa proteger a informação de alterações indevidas
    - Confidencialidade
        - Princípio que visa manter uma informação confidencial
    - Disponibilidade
        - Princípio que visa garantir que um recurso e/ou informação esteja disponível
    - Identificação
        - Princípio que visa indentificar uma entidade
    - Autenticação
        - Princípio que visa verificar a entidade e suas credenciais
    - Autorização
        - Princípio que visa autorizar a entidade dentro de um sistema
    - Não Repúdio
        - Princípio que visa evitar que uma entidade negue suas ações em um sistema

# ICMP Ping

1. O que é ICMP?
    - O ICMP (Internet Control Message Protocol), é um protocolo integrante do Protocolo IP utilizado para fornecer relatórios de erros à fonte original.
2. O que é o PING?
    - O ping é uma ferramenta que usa o protocolo ICMP para testar a conectividade entre nós. É um comando disponível praticamente em todos os sistemas operacionais que consiste no envio de pacotes para o equipamento de destino e na "escuta das respostas. Contemplando o Princípio de 'DISPONIBILIDADE'
3. Ferramenta PING simples em Python
    - Biblioteca 'os'. Este módulo fornece uma maneira simples de usar funcionalidades que são dependentes de sistema operacional
4. Ferramenta PING mútiplo em Python
    - Bibliotecas 'os' e 'time'
  

```python
"""
Criando uma ferramenta PING simples em Python
"""
import os


IP_OU_HOST = "www.google.com"

print("#" * 60)
os.system(f'ping -n 6 {IP_OU_HOST}')
print("#" * 60)
```

```python
"""
Criando uma ferramenta PING mútiplo em Python
"""
import os
import time


with open('hosts.txt', encoding="utf-8") as file:
    dump = file.read()
    dump = dump.splitlines()

    for ip in dump:
        os.system(f'ping -n 2 {ip}')
        time.sleep(2)
```


# Biblioteca Socket

1. O que a Biblioteca Socket?
    - Está biblioteca fornece acesso de baixo nível à interface de rede.
    - O S.O fornece a API socket que relaciona o programa com a rede
2. Desenvolvimento de um cliente TCP:
    - O TCP (Transmission Control Protocol) ou Protocolo de Controle de Transmissão é um dos protocolos de comunicação, que dão suporte a rede global Internet, verificando se os dados são enviados na sequência correta e sem erros.
    - Nosso programa verificará se dados são enviados de maneira íntegra
    - Seguindo o Princípio da INTEGRIDADE!
3. Desenvolvimento de um cliente UDP:
    - O UDP (User Datagram Protocol) ou Protocolo de Datagrama de usuário é um protocolo simples da camada de transporte que permite que a aplicação envie um datagrama dentro num pacote IPv4 ou IPv6 a um destino, porém sem qualquer tipo de garantia que o pacote chegue corretamente.
    - Garantindo o Princípio de DISPONIBILIDADE!
4. Desenvolvimento de um Server!


```python
"""
Desenvolvendo um Script cliente TCP
"""
import socket
import sys


def main():
    """
    Função de conexão TCP
    """
    try:
        # Objeto de conexão
        obj_connection = socket.socket(
            family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0)
    except socket.error as error:
        print("A conexão falhou !!!".upper())
        print(f"Erro: {error}")
        sys.exit()

    print("Socket criado com sucesso".title())

    host_alvo = "google.com"
    porta_alvo = "80"

    try:
        obj_connection.connect((host_alvo, int(porta_alvo)))
        print(
            f"Cliente TCP conectado com Sucesso no Host: {host_alvo} e na Porta: {porta_alvo}")
        # Vai esperar 2 segundos para encerrar a conexão
        obj_connection.shutdown(2)
    except socket.error as error:
        print("A conexão falhou!!!".upper())
        print(f"Erro --> {error}")
        sys.exit()


if __name__ == "__main__":
    main()
```

```python
"""
Desenvolvendo um Script cliente UDP
"""
import socket


ObjConection = socket.socket(
    family=socket.AF_INET,
    type=socket.SOCK_DGRAM
)

print("Cliente Socket Criado Com Sucesso!!!".upper())

HOST = "localhost"
PORTA = 5433
MENSAGEM = "Olá Servidor!"

try:
    print(f"Cliente: {MENSAGEM}")
    ObjConection.sendto(MENSAGEM.encode(), (HOST, PORTA))

    dados, servidor = ObjConection.recvfrom(4096)
    dados = dados.decode()
    print(f"Cliente: {dados}")
finally:
    print("Cliente: Fechando a Conexão")
    ObjConection.close()

```


```python
"""
Desenvolvendo um Script de SERVIDOR
"""
import socket


ObjConection = socket.socket(
    family=socket.AF_INET,
    type=socket.SOCK_DGRAM
)

print("Cliente Socket Criado Com Sucesso!!!".upper())

HOST = "localhost"
PORTA = 5433

ObjConection.bind((HOST, PORTA))

MENSAGEM = "Servidor: Olá Cliente"

while True:
    dados, endereco = ObjConection.recvfrom(4096)
    if dados:
        print("Servidor enviando mensagem...")
        ObjConection.sendto(dados + (MENSAGEM.encode()), endereco)

```



# Desenvolvimento de Ferramentas

1. O que é a Biblioteca random?
    - Esta biblioteca implementa geradores de números pseudoaleatórios para várias distribuições.
    - Esta biblioteca será utilizada no gerador de senhas para randomizar letras e números e a cada execução do programa gerar uma nova senha aleatória.
    - Garantindo o Princípio de AUTENTICAÇÃO e CONFIDENCIALIDADE!
2. O que é um Hash?
    - O hash é como se fosse um identificador único gerado através de um algoritmo que vai analisar byte a byte de determinado dado para gerar de forma única, um determinado código que só aquele arquivo terá. Se neste mesmo arquivo um único bit for alterado o hash gerada será diferente.
    - https://md5decrypt.net/en/
    - Garantindo o Princípio de INTEGRIDADE!
3. o que é a biblioteca hashlib?
    - Esta biblioteca implementa uma interface comum para muitos algoritmos de hash seguro como SHA1, SHA256, MD5 entre outros.
    - Usaremos esta biblioteca em nosso comparador de hashes para comparar dois arquivos.
4. O que é Multithreading?
    - Thread é o processo e no ambiente multithread, cada processo pode responder a várias solicitações concorrentemente ou mesmo simultaneamente. (Ex: Navegadores, abrindo novas abas)
5. O que é a biblioteca threading?
    - Esta biblioteca constrói interface de alto nível para processamento usando o módulo Thread, de mais baixo nível, ou seja relação direta com o processador.
6. O que é a biblioteca ipaddress?
    - Esta biblioteca tem a capacidade de criar, manipular endereços IP do tipo IPv4, IPv6 e até redes inteiras.

# Desenvolvendo um Gerador de Senhas:

- Bibliotecas:
    1. random
    2. string
 

```python
import random
import string


tamanho = 16

Chars = string.ascii_letters + string.digits + '!@#$%&*()-=+,.;:/?'

print(Chars, end="\n\n")

rnd = random.SystemRandom()

# Senha Forte Gerada
password_strong = "".join(rnd.choice(Chars) for i in range(tamanho))
print(
    "Senha randomicamente "
    "gerada classificada como forte: \n"
    f"{password_strong}"
    )
```

# Desenvolvendo um comparador de Hashes

Usaremos a biblioteca Hashlib
    - Implementa uma interface comum para muitos algoritmos de hash seguro como SHA1, SHA256, MD5 entre outros.


```python
import hashlib


arquivo1 = 'a.txt'
arquivo2 = 'b.txt'

hash1 = hashlib.new('ripemd160')
hash1.update(open(arquivo1, 'rb').read())

hash2 = hashlib.new('ripemd160')
hash2.update(open(arquivo2, 'rb').read())

if (hash1.digest() != hash2.digest()):
    print(f"O arquivo: {arquivo1} é diferente do arquivo: {arquivo2}!!!".title())
    print(f'O hash do arquivo a.txt é: {hash1.hexdigest()}\n'
          f'O hash do arquivo b.txt é: {hash2.hexdigest()}'
          )
else:
    print(f"O arquivo: {arquivo1} é igual ao arquivo: {arquivo2}".title())
```

# Usando threads

```python
from threading import Thread
import time


def carro(velocidade, piloto):
    trajeto = 0
    while trajeto <= 100:
        print(f'Piloto: {piloto} Km: {trajeto}\n')
        trajeto += velocidade
        time.sleep(0.5)


thread_carro1 = Thread(target=carro, args=[1, 'Rodrigo'])
thread_carro2 = Thread(target=carro, args=[2, 'Pamêla'])

thread_carro1.start()
thread_carro2.start()
```

# Usando Ips com a lib ipaddress


```python
import ipaddress


ip = '192.168.0.1'
rede = '192.168.0.0/24'

endereco = ipaddress.ip_address(ip)
rede = ipaddress.ip_network(rede)

print(endereco + 2000, "\n")
for ips in rede:
    print(ips)
```

# Desenvolvimento de ferramentas - Parte 2

1. Desenvolvendo um Gerador de Hashes
2. Desenvolvendo um Gerador de Wordlists
3. Desenvolvendo um Web Scraping
4. Desenvolvendo um Web Crawler

# Fazendo um gerador de Hashes


```python
"""
Scripts Gerador de Hashs
"""
import hashlib

string = input("Digite o texto a ser gerado a Hash: ")

menu = int(input(
"""
### MENU - ESCOLHA UM TIPO DE HASH ###
1 - MD5
2 - SHA1
3 - SHA256
4 - SHA512
ESCOLHA O HASH QUE DESEJA GERAR: 
"""
))

if menu == 1:
    resultado = hashlib.md5(string.encode('utf-8'))
    print(f"O hash MD5 da string é: {resultado.hexdigest()}")
elif menu == 2:
    resultado = hashlib.sha1(string.encode('utf-8'))
    print(f"O hash SHA1 da string é: {resultado.hexdigest()}")
elif menu == 3:
    resultado = hashlib.sha256(string.encode('utf-8'))
    print(f"O hash SHA256 da string é: {resultado.hexdigest()}")
elif menu == 4:
    resultado = hashlib.sha512(string.encode('utf-8'))
    print(f"O hash SHA512 da string é: {resultado.hexdigest()}")
else:
    print("Algo de errado não deu certo, tente novamente!!!")
```


# O que são Wordlists?

- Wordlists são arquivos contendo uma palavra por linha.
São utilizados em ataques de força bruta como quebra de autenticação, 
pode ser usada para testar a autenticação e confidencialidade de um sistema.

# Bibliotecas

- Itertools: Está biblioteca fornece condições para iterações como permutação e combinação.
- Usaremos esta biblioteca para gerar uma lista com vários caraacteres diferentes e sem repetição de palavras.

```python
"""
Script para criar Word_Lists
"""
import itertools


ctring = input("Escolha a palavra a ser gerada a WordList")

resultado = itertools.permutations(ctring, len(ctring))

for caracteres in resultado:
    print(''.join(caracteres))
```

# Web Scraping

- Um web scraper é uma ferramenta de coleta de dados web, uma forma de mineração que permite a extração de dados de sites da web convertendo os em informação estruturada para posterior análise.

# Bibliotecas necessárias

- BeautifulSoup: É uma biblioteca de extração de dados de arquivos HTML e XML.
- Requests: Permite que você envie solicitações HTTP em Python.



```python
"""
Criando um Web Scraping
"""
from bs4 import BeautifulSoup


import requests


# Ojeto site recebendo o conteudo da requisição http do site...
site = requests.get("https://www.climatempo.com.br/").content

# Objeto soup baixando do site o html
soup = BeautifulSoup(site, 'html.parser')

# Transforma o HTML em String e o print vai exibir o html
# print(soup.prettify())

# Encontrar a tag <p> com a classe especificada
dado = soup.find("p", class_="-gray _flex _align-center")

# Encontrar as tags <img> dentro da tag <p>
imagens = dado.find_all("img")

# Iterar sobre as tags <img> e seus respectivos textos
for img in imagens:
    alt_text = img.get("alt", "")
    
    # Encontrar o próximo elemento que contém o texto da temperatura
    temperatura_element = img.find_next(string=True)

    temperatura = temperatura_element.strip()
    
    src = img.get("src", "")
    print(f"{alt_text}: {temperatura}, Src: {src}")
```


# Desenvolvendo um Web Crawler

- Web Crawler é usado para encontrar, ler e indexar páginas de um site. É como um robô que captura informações de cada um dos links que encontra pela frente, cadastra e compreende o que é mais relevante. (palavras - chaves).

- Muito utilizado em levantamento de informações em um processo de pentest.

# Bibliotecas necessárias

- Beautifulsoup: É uma biblioteca de extração de dados de arquivos HTML e XML.

- Operator: Exporta um conjunto de funções eficientes correspondentes aos operadores intrÍcicos do python como: + - * / not and.

- Collections: Nos ajuda a preencher e manipular eficientemente as estruturas de dados como tuplas, dicionários e listas.


```python
"""
Script, Criando um Web Crawler
"""
import requests
import operator


from bs4 import BeautifulSoup
from collections import Counter


def start(url):
    """
    Função para buscar os dados do link, e trazer todo o HTML
    """
    word_list = []
    source_code = requests.get(url).text
    soup = BeautifulSoup(source_code, 'html.parser')

    for dados in soup.findAll('div', {'class': 'entry-content'}):
        content = dados.text
        words = content.lower().split()

        for dados_em_words in words:
            word_list.append(dados_em_words)
        clean_wordlist(word_list)


def clean_wordlist(word_list):
    """
    Função que faz a limpeza de uma Word List
    """
    clean_list = []
    for word in word_list:
        symbols = '!@#$%^&*()_-+={[}]|\;:"<>?/., '

        for i in range(0, len(symbols)):
            word = word.replace(symbols[i], '')

        if len(word) > 0:
            clean_list.append(word)
    create_dict(clean_list)


def create_dict(clean_list):
    """
    Função que cria um dicionário de palavras após receber uma lista limpa
    de uma Word List
    """
    word_count = {}

    for word in clean_list:
        if word in word_count:
            word_count[word] += 1
        else:
            word_count[word] = 1

    for key, value in sorted(word_count.items(),
                               key = operator.itemgetter(1)
                               ):
        print("% s : % s " % (key, value))
    
    c = Counter(word_count)
    top = c.most_common(10)
    print(top)


if __name__ == '__main__':
    start("https://www.geeksforgeeks.org/python-programming-language/?ref=leftbar")
```


# Desenvolvendo ferramentas parte 3

1. Desenvolvendo um Verificador de Telefone
    - Bibliotecas:
        - phonenumbers: fornece vários recursos, como informações básicas de um número de telefone, validação de um número de telefone, etc.
2. Desenvolvendo um Ocultador de Arquivos
    - Bibliotecas:
        - ctypes: fornece tipos de dados compatíveis com C e permite funções de chamada em DLLs ou bibliotecas compartilhadas.
3. Desenvolvendo um Verificador de IP Externo
    - Bibliotecas:
        - re: Permite operações com expressões regulares
        - json: Fornece operação de codificação e decodificação JSON
        - urllib.request import urlopen: Funções e classes que ajudam a abrir URLs
4. Ferramenta Gráfica para Abrir o Navegador
    - Bibliotecas:
        - webbrowser: fornece uma interface de alto nível para permitir a exibição de documento Web aos usuários.
        - tkinter: fornece interface padrão do Python para o kit de ferramentas gráficas Tk.

```python
"""
Script que faz a verificação de um Telefone
"""
import phonenumbers


from phonenumbers import geocoder


phone = input('Informe o Telefone: ')
phone_number = phonenumbers.parse(phone)

print(geocoder.description_for_number(phone_number, 'pt'))
```

```python
"""
Script que faz a ocultação de arquivos no Windows
"""
import ctypes


atributo_ocultar = 0x02

retorno = ctypes.windll.kernel32.SetFileAttributesW('ocultar.txt', atributo_ocultar)

if retorno:
    print("Arquivo foi ocultado")
else:
    print("Arquivo não foi ocultado")

```

```python
"""
Scritp Verificador de IP EXTERNO
"""
import re
import json


from urllib.request import urlopen


url = 'https://ipinfo.io/json'

request = urlopen(url)

datas = json.load(request)

print(f" {datas['city']}\n",
      f"{datas['country']}\n",
      f"{datas['ip']}\n",
      f"{datas['loc']}\n",
      f"{datas['org']}\n",
      f"{datas['postal']}\n",
      f"{datas['readme']}\n",
      f"{datas['region']}\n",
      f"{datas['timezone']}"
      )

```


```python
"""
Ferramenta Gráfica para Abrir o Navegador
"""
import webbrowser
from tkinter import *


root = Tk( )

root.title('Abrir Browser')
root.geometry('300x200')

def google():
    webbrowser.open('www.google.com')


mygoogle = Button(root, text='Abrir o Google', command=google).pack(pady=20)
root.mainloop()

```
