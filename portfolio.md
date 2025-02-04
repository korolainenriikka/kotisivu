---
layout: default
title: Rekrytoijille
permalink: /portfolio/
---

# Portfolio

Eli merkityksensä mukaisesti: mitä on tullut tehtyä. Täältä löytyy listattuna koko projektihistoriani kaikkine kokeiluineen, valmistunein, suunnilleen valmistunein ja vähemmän valmistunein osin, kaunistelematta, mutta toisaalta, väheksymättäkään.

Toivottavasti historiakatsaus on rekrytoijalle tai muuten vaan internetissä surffailijalle jossain määrin hyödyksi.

Aikajärjestys on käänteisen kronologinen, ja jokaiseen liittyy GitHub-linkkinsä. Tätä sivua voi muutenkin pitää parempana pääsynä GitHubini sisältöön, kun tietää, mitä mikäkin projekti on pyrkinyt tekemään ja mitä muuta taustatietoa asiaan liittyy.

### Fossiilikatalogien OCR-digitointiprojekti

Projekti alkoi Helsingin luonnontieteellisen museon ja Kenian kansallismuseon yhteisesti tilaamana opiskelijaprojektina, jossa digitoimme käsin kirjoitettuja ja skannattuja fossiililöydöstaulukoita.
Huomasin Azure Vision -API:n toimivan tässä mainiosti, joten käytimme Azurea sanojen lukemiseen sijainteineen.
Tämän jälkeen toteutimme json-datan muunnon taulukoiksi heuristiikoilla ja klusteroinnilla, tunnistimme taulukoiden pistemerkinnät värisegmentoinnilla, jälkiprosessoimme tuloksia latinalaisten nimien sekä OpenAI:n API:lla, sekä toteutimme Flaskilla web-sovelluksen tulosten manuaaliseen tarkastukseen.
Projekti oli salassapitosopimuksen alainen, joten koodia emme valitettavasti voineet julkaista.
Projekti oli hauska ja kiinnostava, joten samoilla vauhdeilla rakentelin oman OCR-työkaluni, joka lukee hammasmerkintöjä ja on ilokseni jo jatkokäytössä.
OCR-projektista kirjoitin myös maisterin tutkielmani otsikolla "Fine-tuned Optical Character Recognition for Dental Fossil Markings" arvosanalla 5.
Työkalun toteutin vertailemalla erilaisia CNN- ja transformer-arkkitehtuureja sekä transfer learning- menetelmiä.

**GitHub**:
* <a href="https://github.com/korolainenriikka/fine-tuned-ocr-for-dental-markings">https://github.com/korolainenriikka/fine-tuned-ocr-for-dental-markings</a>
* <a href="https://github.com/korolainenriikka/theses/blob/master/Korolainen_Riikka_Mastersthesis_2024.pdf">https://github.com/korolainenriikka/theses/blob/master/Korolainen_Riikka_Mastersthesis_2024.pdf</a>

**Teknologiat**: Python, PyTorch, Azure

**WSJ-artikkeli aiheen taustoista**: <a href="https://www.wsj.com/world/africa/nairobi-national-museum-natural-history-leakey-832f0262">https://www.wsj.com/world/africa/nairobi-national-museum-natural-history-leakey-832f0262</a>

<hr/>

### Toimintoja Shuriken-toiminnanohjausjärjestelmään

Yhden opintojen aikaisen välivuoden sekä maisterintutkinnon aikaisten kesien ajan, vuosina 2022-2025, toimin full-stack kehittäjänä kehittämässä
verkkokaupan toiminnanohjausjärjestelmää. Pienemmässä yrityksessä pääsin ilokseni heti isoihin saappaisiin, ja yksin vastuuseen toteuttamaan mm. 
seuraavanlaisia toimintoja: Pricer-hintanäyttöjen integraation, Google Analyticsin sekä Facebook Conversion API:n tukemisen, releiden kytkemistä myöten
noutoautomaatin toteutuksen hyllytystyökaluineen, sekä monenlaisia korjauksia legacy-koodiin.

Muutamat toteuttamani toiminnot näkyvät asiakaspuolelle asti:

Ajanvarauskalenteri: <a href="https://frakkipalvelunam.fi/calendar.php">https://frakkipalvelunam.fi/calendar.php</a>

Mittatilaustuotteiden tuki: <a href="https://madeinfinlandshop.fi/p37255/tylli-lokki-matto">https://madeinfinlandshop.fi/p37255/tylli-lokki-matto</a>

**Teknologiat**: PHP, TypeScript, PHPUnit, Codeception

<hr/>

### Housing AI

Datatieteen johdatuskurssille toteutettu miniprojekti. Ennustimme asuntojen kysynnän muutoksia 
suuralueittain Helsingissä ja toteutimme pienen web-sovelluksen tulosten visualisointiin.

**Github**: <a href="https://github.com/korolainenriikka/housing-AI">https://github.com/korolainenriikka/housing-AI</a>

**Teknologiat**: Python, Pandas, StreamLit

<hr/>

### Kotisivu

Eli sivu, jota lueskelet. Ensisijainen idea taisi lähteä siitä, että olisi siistiä olla tyyppi, jolla on omat kotisivut. Noin muuten, työkontekstia ajatellen, tämä mahdollistaa hirmuisen kätevästi osaamiseni ja tekemiseni esittelyn mielestäni järkevimmällä tavalla kaikille kiinnostuneille yhdestä paikasta käsin. Ei-työmielessä, kotisivu mahdollistaa myös kaikenlaisten hassujen haaveiden, kuten vaikkapa kasvikennelin omistamisen, tai matkakirjailujen, helpon toteuttamisen. Sekin on kätevää, ja erityisen mukavaa.

**GitHub**: <a href="https://github.com/korolainenriikka/kotisivu">https://github.com/korolainenriikka/kotisivu</a>

**Teknologia**: Jekyll

<hr/>

### MLOps-skriptejä VesselAI-projektiin

Tutkimusavustajana kesällä 2021 koin paitsi ensikosketukseni koneoppimiseen, tein myös jonkin verran IaC- sekä MLOps-juttuja merenkulun 
automaatiota edistävään EU:n laajuiseen <a href="https://vessel-ai.eu">VesselAI</a>-projektiin. Linkkinä on monta repositoriota, osassa on koneoppimisrepositorioita joita käytin erilaisten automatisoitujen pipelinejen kokeiluun, yhdessä on konfiguraatiotiedostoja noiden systeemien pyörittämiseen OpenStack-pilvipalvelussa, ja yhdessä on MLOps-konfiguraatioita työkaverin tekemän datansiivouskoodin päällä.
Tein projektiin myös kandidaatin tutkielmani otsikolla "Enabling efficient model maintenance in a
big data system: a case study" arvosanalla 5 koneoppimispalveluiden monitoroinnista ja ylläpidosta projektin kontekstissa.

**GitHub**:
* <a href="https://github.com/korolainenriikka/multistep_word_classification">https://github.com/korolainenriikka/multistep_word_classification</a>
* <a href="https://github.com/korolainenriikka/mlflow_test">https://github.com/korolainenriikka/mlflow_test</a>
* <a href="https://github.com/korolainenriikka/mlflow_on_openstack_automated">https://github.com/korolainenriikka/mlflow_on_openstack_automated</a>
* <a href="https://github.com/korolainenriikka/cleaning_scripts">https://github.com/korolainenriikka/cleaning_scripts</a>
* <a href="https://github.com/korolainenriikka/theses/blob/master/Korolainen%20Riikka%20Enabling%20efficient%20model%20maintenance%20in%20a%20big%20data%20system%3A%20a%20case%20study.pdf.pdf">https://github.com/korolainenriikka/theses/blob/master/KorolainenRiikkaEnabling_efficient_model_maintenance_in_a_big_data_system_A_case_study.pdf</a>

**Teknologiat**: Python, Numpy, Pandas, MLflow, Ansible, OpenStack

<hr/>

### DevOps-kyselytyökalu
Yliopiston ohjelmistotuotantoprojektin puitteissa tuotettu projekti, asiakasyrityksen opiskelijatyönä tilaamana, jonka tarkoituksena oli mahdollistaa uusien asiakkaiden löytäminen tarjoamalla mahdollisuus DevOps-kykyjen kartoittamiseen. Kahdeksan hengen ryhmässä pääsi paitsi tekemään ilahduttavan paljon yhteistyötä, myös oppimaan ryhmätyöskentelyä.

**GitHub**: <a href="https://github.com/Devops-ohtuprojekti/DevOpsCSAOS">https://github.com/Devops-ohtuprojekti/DevOpsCSAOS</a>

**Teknologiat**: Next.js, Node.js, PostgreSQL, Robot Framework, Styled components, GitHub Actions, Docker, Sequelize, Heroku

<hr/>

### Teetietokanta
Tietoturvaprojekti yliopiston tietoturvakurssin puitteissa. Yksinkertainen parin sivun web-sovellus, joka sisältää muutaman tietoturva-aukon. 

**GitHub**: <a href="https://github.com/korolainenriikka/cybersecuritybaseproject">https://github.com/korolainenriikka/cybersecuritybaseproject</a>

**Teknologiat**: Django

<hr/>

### Reaktor assignment
Tein kesän 2021 Reaktor-työnhakutehtävän, varastonhallinta-frontendin hitaan  legacy-API:n päälle. Haaste osoittautui hankalaksi välimuistin käytön osalta ja jäi sivuun saatuani muita töitä, mutta meni hyvästä TypeScript-harjoittelusta.

**Teknologiat**: TypeScript, React, React-Query

**GitHub**: <a href="https://github.com/korolainenriikka/Reaktor_junior_assignment">https://github.com/korolainenriikka/Reaktor_junior_assignment</a>

<hr/>

### Othello-botti
Kokeiltiin erään opiskeluystäväni kanssa kumpi tekee paremman pelibotin algoritmikurssin puitteissa. Koodattiin myös yhteinen pelialusta, jolla mittelö käytiin. Tekniikkana oli itselläni minimax-algoritmi alpha-beta karsinnalla, progressiivisesti syvenevällä pelipuulla sekä transpositiotaululla maustettuna (kiinnostunut voi etsiä näistä tarkemmin internetistä, selittäminen olisi vaivalloista). Hävisin kisan kun lähdin hifistelemään algotekniikoilla, mutta hauskempaa tämä oli kuin parametrien manuaalinen näpräily. Lisäksi transpositiotaulu meni hieman yli hilseen, muut tekniikat sain toimimaan kivasti.

**Teknologiat**: Java, hurjat algoritmikikat

**GitHub**: 
* Botti: <a href="https://github.com/korolainenriikka/Jani">https://github.com/korolainenriikka/Jani</a>
* Pelialusta: <a href="https://github.com/vuolen/othello-core">https://github.com/vuolen/othello-core</a>

<hr/>

### Bobit 1 & 2
Korkealentoisen, nopean ja monesta kiinnostuneen kaikkialla päsmäröivän ajattelun kääntöpuolena on  se, että arkielämän triviaalit asiat pääsevät välillä unohtumaan. Tällä on silloin tällöin epäonnisia seurauksia, kuten välikokeen ajan unohtaminen. Päättelin mahdollisesti voivani ratkaista ongelman tekemällä itselleni assistentin. Siinähän olisi *suurmiehen meininkiä*, jos omistaisi itse itselleen koodaaman assistentin.

Ensimmäinen versio oli JavaFX-sovellus, joka teki kaikenmoista hauskaa, kuten soitti Harry Potter -ambient soundeja työajastajan raksuttaessa, mutta ongelmana oli mobiiliversion puute. Bob2 puolestaan webbisovelluksena korjasi tämän, mutta lopulta käyttö unohtui, sillä pilvipalveluiden ilmaiset versiot latasivat sivun aivan onnettoman hitaasti. React-harjoittelu oli kuitenkin paikallaan.

**Teknologiat**: Java, JavaFX, FXML, React, Node.js, MongoDB, Heroku, lyijykynä

**GitHub**:

* Bob the personal assistant: <a href="https://github.com/korolainenriikka/BobThePersonalAssistant-ohte2020">https://github.com/korolainenriikka/BobThePersonalAssistant-ohte2020</a>
* Bob2: <a href="https://github.com/korolainenriikka/Bob2">https://github.com/korolainenriikka/Bob2</a>

<hr/>

### Workout Logger

Eli ensimmäinen katsaus Pythonin maailmaan. Koulun tietokantasovelluksen kurssilla tehty projekti oli sekä ensimmäinen python-sovellus, että ensimmäinen webbisovellus. Projektin tekeminen tuntui kaiken uutuuden vuoksi vallan sekavalta eikä lopputulos mitenkään häikäissyt ominaisuuksiltaan, mutta oikein hyvää harjoittelua oli tämäkin.

**Teknologiat**: Python, Flask

**GitHub**: <a href="https://github.com/korolainenriikka/WorkoutLogger-tsoha">https://github.com/korolainenriikka/WorkoutLogger-tsoha</a>
