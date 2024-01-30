package org.saml;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.util.encoders.UTF8;
import org.w3c.dom.*;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xmlutil.GenerateSAML;

import com.onelogin.saml2.authn.AuthnRequest;
import com.onelogin.saml2.settings.Saml2Settings;

/**
 * Servlet implementation class SAML
 */
public class SAML extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public SAML() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		String saml_req="", relay_state="";
		
		saml_req = request.getParameter("SAMLRequest");
		relay_state = request.getParameter("RelayState");
		//String samlRequest = java.net.URLDecoder.decode(saml_req, StandardCharsets.UTF_8);
		byte[] decodedSAMLRequest = Base64.getDecoder().decode(saml_req);
		int resultLength = 0;
		Inflater decompressor = new Inflater(true);
		decompressor.setInput(decodedSAMLRequest);
		byte[] inflatedSamlReq = new byte[4096];
		try {
			resultLength = decompressor.inflate(inflatedSamlReq);
		} catch (DataFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		finally {
			decompressor.end();
		}
		String final_saml_req = new String(inflatedSamlReq, 0, resultLength, StandardCharsets.UTF_8);
		String urlMcAfee = "https://idstg.mcafee.com";
		//Parse the incoming SamlRequest
		String samlResponse = "";
	    try {
	    	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            ByteArrayInputStream input = new ByteArrayInputStream(final_saml_req.getBytes(StandardCharsets.UTF_8));
            Document document = builder.parse(input);

            // Extract and print values (adjust the XPath expressions based on your XML structure)
            NodeList issuerNodeList = document.getElementsByTagName("saml:Issuer");
            String issuer = issuerNodeList.item(0).getTextContent();
            System.out.println("Issuer: " + issuer);

            NodeList nameIDNodeList = document.getElementsByTagName("samlp:AuthnRequest");
            
            Node nodeID = nameIDNodeList.item(0).getAttributes().getNamedItem("ID");
            String requestId = nodeID.getNodeValue();
            System.out.println("ID: " + requestId);
            
            GenerateSAML generateSAML = new GenerateSAML();
    		samlResponse = generateSAML.generateSAML(requestId);
    		System.out.println("The saml response is " + samlResponse);
			
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	    StringBuilder responseToClient = new StringBuilder(); 
	    responseToClient.append("<html><body onload=\"document.forms['saml'].submit()\"><form id=\"saml\" name=\"saml\" action=\"").append(urlMcAfee).append("/login/callback?connection=saml-test\" method=\"post\"> ");
		responseToClient.append("<input type=\"hidden\" id=\"RelayState\" name=\"RelayState\" value=\"").append(relay_state).append("\"> ");
		responseToClient.append("<input type=\"hidden\" id=\"SAMLResponse\" name=\"SAMLResponse\" value=\"").append(samlResponse).append("\"> ");
		responseToClient.append("<input type=\"submit\" value=\"Submit\"></form></body></html>");
		log("HTML : " + responseToClient.toString());
											
		response.setStatus(HttpServletResponse.SC_OK);
		response.getWriter().write(responseToClient.toString());
		response.getWriter().flush();
		
		
		//response.getWriter().append("Served at: ").append(request.getContextPath() + " with SAML request " + saml_req + " that is decoded as " + final_saml_req);
	}

}
