package org.saml;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Servlet implementation class home
 */
public class home extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public home() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		//response.getWriter().append("Served at: ").append(request.getContextPath());
		response.sendRedirect("https://idstg.mcafee.com/authorize?client_id=fmfjTFkOnTBnnbgv99Sn0s97R0goSsgv&connection=saml-test&response_type=id_token&scope=openid+profile&response_mode=form_post&redirect_uri=https%3a%2f%2fhome.mcafee.com%2fSecure%2fAuth0Handler.ashx&affid=911&nonce=asdgasdf");
	}

}
