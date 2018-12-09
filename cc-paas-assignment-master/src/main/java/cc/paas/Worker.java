package cc.paas;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.DecoderException;
import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.DatastoreServiceFactory;
import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.EntityNotFoundException;
import com.google.appengine.api.datastore.Key;
import com.google.appengine.api.datastore.KeyFactory;
import com.google.appengine.api.datastore.Query;
import com.google.appengine.api.datastore.Query.Filter;
import com.google.appengine.api.datastore.Query.FilterOperator;
import com.google.appengine.api.datastore.Query.FilterPredicate;
import com.google.appengine.api.datastore.Transaction;

import cc.paas.BruteForce;
import cc.paas.EapolInfo;

@WebServlet(
    name = "Worker",
    urlPatterns = {"/worker"}
)
public class Worker extends HttpServlet {
	
  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
  		throws IOException {
	  
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response) 
	      throws IOException {
	  
	  List<String> dictionary = new ArrayList<String>();
	  
	  String STA=null;
	  String BSSID=null;
	  String ANonce=null;
	  String SNonce=null;
	  String MIC=null;
	  Integer Version=null;
	  String SSID=null;
	  String secondFrame=null;	
		
	  //Get data from master
	  MIC=request.getParameter("MIC");
	  Integer startIndex=Integer.parseInt(request.getParameter("startIndex"));
	  Integer endIndex=Integer.parseInt(request.getParameter("endIndex"));
	  
	  //Get data from datastore
	  DatastoreService datastore = DatastoreServiceFactory.getDatastoreService();
	  Filter eapolFilter=new FilterPredicate(Entity.KEY_RESERVED_PROPERTY, FilterOperator.EQUAL, KeyFactory.createKey("eapolInfo", MIC));
	  Filter dictionaryFilter=new FilterPredicate(Entity.KEY_RESERVED_PROPERTY, FilterOperator.EQUAL, KeyFactory.createKey("dictionary", MIC));
	  Query eapolQuery = new Query("eapolInfo").setFilter(eapolFilter);
	  Query dictionaryQuery = new Query("dictionary").setFilter(dictionaryFilter);
	  
	  //There will only ever be a single eapolInfo with the MIC as a key
	  Entity eapolEntity=datastore.prepare(eapolQuery).asSingleEntity();
	  
	  STA=(String) eapolEntity.getProperty("STA");
	  BSSID=(String) eapolEntity.getProperty("BSSID");
	  ANonce=(String) eapolEntity.getProperty("ANonce");
	  SNonce=(String) eapolEntity.getProperty("SNonce");
	  //We already have the MIC so we're skipping that
	  Version=Math.toIntExact((Long) eapolEntity.getProperty("Version"));
	  SSID=(String) eapolEntity.getProperty("SSID");
	  secondFrame=(String) eapolEntity.getProperty("secondFrame");
	  
	  //Load the dictionary. This is probably a really stupid way to do it, but I'm tired
	  Entity dictionaryEntity=datastore.prepare(dictionaryQuery).asSingleEntity();
	  for(Integer i=startIndex;i<=endIndex;i++)
	  {
		  dictionary.add((String) dictionaryEntity.getProperty(i.toString()));
	  }
	  
	  //Do the work
	  
	  Result result=null;
	  
	try {
		EapolInfo info;
		info = new EapolInfo(STA, BSSID, ANonce, SNonce, MIC, Version, SSID, secondFrame);
		BruteForce force=new BruteForce(info, dictionary);
		result=force.runAttack();
		
		
		
	} catch (DecoderException e) {
		response.sendError(500, "Error creating EapolInfo object!");
	} 
	
	//do the transaction
	
	//And now we run the transaction. We need a transaction to ensure other workers don't nuke our results
	
	Entity task;
	Transaction txn=datastore.beginTransaction();
	try
	{
		Key resultKey = KeyFactory.createKey("result", MIC);
		Entity resultEntity = datastore.get(resultKey);
		Long entriesChecked=(Long) resultEntity.getProperty("EntriesChecked");
		entriesChecked+=result.EntriesChecked;
		resultEntity.setProperty("EntriesChecked", entriesChecked);
		if(result.PasswordFound==1)
		{
			resultEntity.setProperty("PasswordFound", 1);
			resultEntity.setProperty("Password", result.Password);
		}
		datastore.put(txn, resultEntity);
		txn.commit();		
	} catch (EntityNotFoundException e) {
		response.sendError(500, "Entity with key " + MIC + " not found in result!");
	} finally {
		if(txn.isActive())
			txn.rollback();
	}
			
			
	
}
  
}