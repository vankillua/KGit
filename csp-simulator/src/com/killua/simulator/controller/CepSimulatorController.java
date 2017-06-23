package com.killua.simulator.controller;

import java.util.Calendar;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.killua.simulator.service.ClientBlackListChkService;

import org.apache.commons.lang.StringUtils;

@Controller
public class CepSimulatorController {

	private static final Logger LOG = LoggerFactory.getLogger(CepSimulatorController.class);
	
	@Autowired
//	@Qualifier("clientBlackListChkService")
	private ClientBlackListChkService clientBlackListChkService;
	
	@RequestMapping(value = "/clientid", method = RequestMethod.GET)
	public ResponseEntity<String> getCepCertificate(@RequestParam("srcip") String ip, @RequestParam("srcport") String port, @RequestParam("mqttClientId") String id) {
		System.out.println("Receive a request: srcip[" + ip + "], srcport[" + port + "], mqttClientId[" + id + "].");
		String certificate = "";
		if(StringUtils.isEmpty(ip) || StringUtils.isEmpty(port) || StringUtils.isEmpty(id)) {
			System.out.println("source ip, port, and clientId cannot be null or empty.");
			LOG.error("source ip, port, and clientId cannot be null or empty.");
			return new ResponseEntity<>(certificate, HttpStatus.BAD_REQUEST);
		}
		if(clientBlackListChkService.isBlackList(id)) {
			System.out.println("The clientid[" + id + "] is in the black list.");
			LOG.error("The clientid[{}] is in the black list.", id);
			return new ResponseEntity<>(certificate, HttpStatus.NO_CONTENT);
		}
		Calendar calendar = Calendar.getInstance();
		int year = calendar.get(Calendar.YEAR);
		int week = calendar.get(Calendar.WEEK_OF_YEAR);
		String yw = String.format("%04d%02d", year, week);
		certificate = "DC=Volvo Cars,DC=Connected Car,L=CN,O=" + year + ",OU=" + yw + ",name=,CN=" + id + ",UID=TEM";
		System.out.println("Vehicle certificate info: " + certificate);
		LOG.info("Vehicle certificate info: {}", certificate);
		return new ResponseEntity<>(certificate, HttpStatus.OK);
	}
}