package cc.paas;

import java.io.IOException;
import java.util.List;

import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.*;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;

import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.DatastoreServiceFactory;
import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.KeyFactory;
import com.google.appengine.api.datastore.Query;
import com.google.appengine.api.datastore.Query.Filter;
import com.google.appengine.api.datastore.Query.FilterOperator;
import com.google.appengine.api.datastore.Query.FilterPredicate;
import com.google.appengine.api.taskqueue.Queue;
import com.google.appengine.api.taskqueue.QueueFactory;
import com.google.appengine.api.taskqueue.TaskOptions;
import com.google.gson.Gson;


@WebServlet(
    name = "MasterService",
    urlPatterns = {"/master"}
)
@MultipartConfig(
	maxFileSize = 10 * 1024 * 1024, // max size for uploaded files
	maxRequestSize = 20 * 1024 * 1024, // max size for multipart/form-data
	fileSizeThreshold = 5 * 1024 * 1024 // start writing to Cloud Storage after 5MB
)
public class Master extends HttpServlet {

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) 
      throws IOException {

	  String MIC=request.getParameter("MIC");
	  
	 //Set the response to JSON
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");
    //Create the gson object that does our serialization
    Gson gson=new Gson();
    //Get the datastore
    DatastoreService datastore = DatastoreServiceFactory.getDatastoreService();
    Filter propertyFilter = new FilterPredicate(Entity.KEY_RESERVED_PROPERTY, FilterOperator.EQUAL, KeyFactory.createKey("result", MIC));
    Query q = new Query("result").setFilter(propertyFilter);
    //We'll always only have one result since we're querying by key and key is unique
    Entity queryResult = datastore.prepare(q).asSingleEntity();
    //Create a result object so we have our JSON properly formatted the way we like it.
    Result result = new Result((Long) queryResult.getProperty("DictionaryEntries"),(Long) queryResult.getProperty("EntriesChecked"),(Long) queryResult.getProperty("PasswordFound"),(String) queryResult.getProperty("Password"));
    response.getWriter().print(gson.toJson(result));

  }
  
  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response) 
	      throws IOException {
	  
	  
	  //Create all the stuff we need and set it to some default state
  
	  String STA=null;
	  String BSSID=null;
	  String ANonce=null;
	  String SNonce=null;
	  String MIC=null;
	  Integer Version=null;
	  String SSID=null;
	  String secondFrame=null;	
	  		
	//Handling multipart form
	ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
	try {
		//Get a list of items in the form
		List<FileItem> items = (List<FileItem>) upload.parseRequest(request);
		//We need this for the file
		String file=null;
		//Handle items
		for(FileItem item : items)
		{
			//If the item is a file
			if(!item.isFormField())
				file = item.getString();
			else //Otherwise it's a field from the form, handle these based on the field name
				switch(item.getFieldName()) {
				case "STA": 
					STA=item.getString();
					break;
				case "BSSID":
					BSSID=item.getString();
					break;
				case "ANonce":
					ANonce=item.getString();
					break;
				case "SNonce":
					SNonce=item.getString();
					break;
				case "MIC":
					MIC=item.getString();
					break;
				case "Version":
					Version=Integer.parseInt(item.getString());
					break;
				case "SSID":
					SSID=item.getString();
					break;
				case "secondFrame":
					secondFrame=item.getString();
					break;
				default: //If we got something we don't recognize there is a problem
					response.sendError(500, "Unknown parameter: " + item.getFieldName() + " with value: " + item.getString());
						break;
					}
		}
		//Split the file by newline
		String[] fileStrings = file.split("\\R");
			
		//Datastore magic. For the key we'll use the MIC. The MIC is a hash of the
		//2nd frame. In order for 2 MICs to match we would have to either have a conflict or
		//have a completely identical frame which is highly unlikely
		//Using the MIC as a key also easily allows our workers to retrieve this data
		
		DatastoreService datastore=DatastoreServiceFactory.getDatastoreService();
		Entity eapolInfo = new Entity("eapolInfo", MIC);
		
		eapolInfo.setProperty("STA", STA);
		eapolInfo.setProperty("BSSID", BSSID);
		eapolInfo.setProperty("ANonce", ANonce);
		eapolInfo.setProperty("SNonce", SNonce);
		eapolInfo.setProperty("MIC", MIC);
		eapolInfo.setProperty("Version", Version);
		eapolInfo.setProperty("SSID", SSID);
		eapolInfo.setProperty("secondFrame", secondFrame);
			
		datastore.put(eapolInfo);	
		
		
		//Once again we can use the MIC as the key for the corresponding dictionary
		Entity dictionary = new Entity("dictionary", MIC);
		//The maximum size of an indexed string is 1500 Bytes, which makes it impossible to store chunks as
				//json or in any other way so we'll have to store individual strings
		//There is probably a lot of reasons to argue that 
		//making 1400 indexes here is a really, really stupid idea
		for(Integer i=0;i<fileStrings.length;i++)
		{
			dictionary.setProperty(i.toString(), fileStrings[i]);
		}
	
		datastore.put(dictionary);
		
		//Create the result object
		
		Entity resultEntity = new Entity("result", MIC);
		
		Result result=new Result(fileStrings.length,0,0,null);
		
		resultEntity.setProperty("DictionaryEntries", result.DictionaryEntries);
		resultEntity.setProperty("EntriesChecked", result.EntriesChecked);
		resultEntity.setProperty("PasswordFound", result.PasswordFound);
		resultEntity.setProperty("Password", result.Password);
		
		datastore.put(resultEntity);
		
		//Create the queue. We only need one so we'll use the default as per the API examples
		
		Queue queue = QueueFactory.getDefaultQueue();
		
		//To add to the queue we will divide the dictionary into blocks with reasonable execution time.
		//Since we can handle about 170 dictionary entries per second, we'll give a block 500 entries
		
		Integer workerCount=fileStrings.length/500;
		
		for(int i=0;i<workerCount;i++)
		{
			String startIndex=Integer.toString(i*500);
			String endIndex=Integer.toString(i*500+499);
			queue.add(TaskOptions.Builder.withUrl("/worker").param("MIC", MIC)
					.param("startIndex", startIndex).param("endIndex", endIndex));
		}
		//The last worker gets a bit less work
		String startIndex=Integer.toString(workerCount*500);
		String endIndex=Integer.toString(fileStrings.length-1);
		queue.add(TaskOptions.Builder.withUrl("/worker").param("MIC", MIC)
				.param("startIndex", startIndex).param("endIndex", endIndex));
		
		
		} catch (FileUploadException e1) {
			response.sendError(500, "Error reading file");
		}
	
		
	
}
  
}