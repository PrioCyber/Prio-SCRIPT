#!/usr/bin/env python
__author__ = 'PRIOCYBER <info@priocyber.com>'

'''
Tool para realizar scanning en elastic y obtener banner en caso de que el
servicio se encuetre abierto a traves de nmap

'''

###########################################
import re
import os
import sys
import argparse
import datetime
import nmap
import requests
import json
import smtplib
from elasticsearch import Elasticsearch
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

###########################################
# Configuracion para el debug
###########################################
debug = 1
os.chdir(os.path.dirname(sys.argv[0]))

###########################################
# Funcion para enviar email
###########################################
def send_mail(message):

	# Credenciales SMTP
	get_date = datetime.date.today()
	fromaddr = 'from_addr'
	toaddrs  = 'to_addr'
	cc = "cc_account"
	password = 'Passwd'
	subject = "Informe de Seguridad " + str(get_date)

	# HTML
	rcpt = cc.split(",") + [toaddrs]
	msg = MIMEMultipart('alternative')
	msg['Subject'] = subject
	msg['From'] = fromaddr
	msg['To'] = toaddrs
	msg['Cc'] = cc

	part = MIMEText(message, 'html')
	msg.attach(part)

	server = smtplib.SMTP('ip_smtp')
	server.ehlo()
	server.starttls()
	server.login(fromaddr,password)
	server.sendmail(fromaddr, rcpt, msg.as_string())
	server.quit()

###########################################
# Funcion para escribir log
###########################################
def write_log(data):

	format = "%a %b %d %H:%M:%S %Y"
	get_date = datetime.datetime.today()
	date = get_date.strftime(format)

	if debug == 0:
		with open("portscan.log", "a") as log:
			log.write(date + " " + data + "\n")
	else:
		print date + " " + data

###########################################
# ELASTICSEARCH QUERY
###########################################
def query(port, top):

	es  = Elasticsearch()
	res = es.search(index="logstash-*", request_timeout=60, body={
    "query": {
    "filtered": {
      "query": {
        "query_string": {
          "query": "*",
          "analyze_wildcard": "true"
        }
      },
      "filter": {
        "bool": {
          "must": [
	     {
              "query": {
                "match": {
                  "action.raw": {
                    "query": "Teardown",
                    "type": "phrase"
                  }
                }
              },
              "query": {
                "match": {
                  "dst_port.raw": {
                    "query": port,
                    "type": "phrase"
                  }
                }
              }
            },
	     {
              "range": {
                "@timestamp": {
                  "gte": "now-24h",
                  "lte": "now",
                  "format": "epoch_millis"
                }
              }
            }
          ],
          "must_not": []
        }
      }
    }
  },
  "size": 0,
  "aggs": {
    "DSTIP": {
      "terms": {
        "field": "dst_ip.raw",
        "size": top,
        "order": {
          "_count": "desc"
       }
      }
    }
  }
})
	return res

html_head = """\
<html>
	<head>
	</head>
	<body>
		<table width="100%" border="1" style="border-collapse: collapse; border-color: #AAAAAA">
			<tbody>
				<tr>
					<td width="50%" style="padding: 4px">
						<span>
							PRIOCYBER SECURITY
							<hr>
							NEXT GENERATION DEFENSE 
						</span>
					</td>
					<td>
						<span>
							<h2>INFORME DE SEGURIDAD</h2>
						</span>
					</td>
				</tr>
			</tbody>
		</table>
		<br />
		<br />
		<br />
		<span style="font-size: 22px"><b>Informe de Seguridad</b></span>
		<br />
		<br />
		<br />
		<table width="100%" border="1" style="border-collapse: collapse">
			<tbody>

"""

html_body = """\
				<tr>
				<th style="text-align: left" width="220px"><b>Direcci&oacute;n IP</b></th>
				<td><b>Detalle</b>
				</tr>
"""

html_footer = """\
			</tbody>
		</table>
		<br />
		<br />
		<hr />
		<span style="font-size: 8pt; font-family: Arial; color: rgb(139, 139, 139);">
			PRIOCYBER &copy; 2016 - Prohibida su reproducci&oacute;n total o parcial a trav&eacute;s de cualquier medio impreso o electr&oacute;nico.
		</span>
		<br />
		<span style="font-size: 8pt; font-family: Arial; color: rgb(139, 139, 139);">
			PRIOCYBER NEXT GENERATION DEFENSE
			<a href="http://www.priocyber.com/">www.priocyber.com</a>
			<a href="mailto:info@priocyber.com"> PRIOCYBER</a>
		</span>
	</body>
</html>
"""

###########################################
# Main
###########################################
if __name__ == "__main__":

	###########################################
	# Argumentos
	###########################################
        parser = argparse.ArgumentParser(description='Port Scanning.')
        #parser.add_argument('-p','--port',help='Puerto a verificar', required=True)
        parser.add_argument('-t','--top',help='Top de muestra', required=True)
        args = parser.parse_args()

	# Flag para enviar alerta
	alert_flag = 0

	# Eejecutamos query asociada al Puerto
	# Los puertos son: 22/TCP - 23/TCP - 1433/TCP - 3389/TCP
	list_port = [21,22,23,1433,3306,3389]
	for check_port in list_port:

		res = query(check_port,args.top)
		for f in res['aggregations']['DSTIP']['buckets']:
			nm = nmap.PortScanner()
			nm.scan(f['key'], str(check_port))

			for host in nm.all_hosts():
				for proto in nm[host].all_protocols():
					lport = nm[host][proto].keys()
					lport.sort()

					if check_port == 3389:
						for port in lport:
							if 'open' in nm[host][proto][port]['state']:
								if nm[host][proto][port]['product']:
									alert_flag = 1
									html_body += '<tr>'
									html_body += '<th style="text-align: left" width="220px">' + host + '</th>'
									html_body += '<td> <b>Puerto:</b>' + str(check_port) + ' <b>Servicio:</b>' + nm[host][proto][port]['name'] + ' <b>Estado:</b>' + nm[host][proto][port]['state'] + ' <b>Producto:</b>' + nm[host][proto][port]['product'] + '</td>'
									html_body += '</tr>'
					else:
						for port in lport:
							if 'open' in nm[host][proto][port]['state']:
								alert_flag = 1
                                                                html_body += '<tr>'
                                                                html_body += '<th style="text-align: left" width="220px">' + host + '</th>'
                                                                html_body += '<td> <b>Puerto:</b>' + str(check_port) + ' <b>Servicio:</b>' + nm[host][proto][port]['name'] + ' <b>Estado:</b>' + nm[host][proto][port]['state'] + ' <b>Producto:</b>' + nm[host][proto][port]['product'] + '</td>'
                                                                html_body += '</tr>'

						#print ('IP Vulnerable: %s, Servicio: %s, Estado: %s, Producto: %s' % (host, nm[host][proto][port]['name'], nm[host][proto][port]['state'], nm[host][proto][port]['product']))

	# Enviamos logs
	if alert_flag:
		email =  html_head + html_body + html_footer
		send_mail(email)
