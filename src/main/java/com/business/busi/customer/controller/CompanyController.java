package com.business.busi.customer.controller;
import java.util.Map;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.business.busi.customer.entity.Company;
import com.business.busi.customer.entity.Customers;
import com.business.busi.customer.entity.Workers;
import com.business.busi.customer.model.CompanyDetails;
import com.business.busi.customer.service.CompanyService;


@RestController
@RequestMapping("company")
@CrossOrigin(origins = "http://localhost:4200", allowedHeaders = "*")
public class CompanyController {
	
	@Autowired
	private CompanyService service;
    
	@PostMapping("saveCompany")
	public Company saveCompanyInfo(@RequestBody Company company) {
		Company companyData = service.saveCompanyInfo(company);
		return companyData;
	}
	
	@GetMapping("getCompanyList")
	public CompanyDetails getCompanyList(@RequestParam(defaultValue = "1") int page,
	        @RequestParam(defaultValue = "10") int size){
		CompanyDetails listOfCompanies = service.getCompanyList(page-1, size);
		return listOfCompanies;
	}
	
	@GetMapping("getCompanyDetailsList")
	public CompanyDetails getCompanyDetailsList(@RequestParam(defaultValue = "1") int page,
	        @RequestParam(defaultValue = "10") int size){
		CompanyDetails listOfCompanies = service.getCompanyDetailsList(page-1, size);
		return listOfCompanies;
	}
	
	@GetMapping("getCompanyById")
	public Optional<Company> getCompanyById(@RequestParam long companyId){
		Optional<Company> companyData = service.getCompanyById(companyId);
		return companyData;
	}
	
	@GetMapping("deleteCompanyById")
	public Map<String,String> deleteCompanyById(@RequestParam long companyId){
		Map<String,String> delRes = service.deleteCompanyById(companyId);
		return delRes;
	}
	
	@PostMapping("updateCompany")
	public Map<String,String> updateCompany(@RequestBody Company company){
		Map<String,String> res = service.updateCompany(company);
		return res;
	}
	
	@GetMapping("getDuplicateCompany")
	public Map<String,String> getDuplicateCompany(@RequestParam long companyId){
		Map<String,String> count = service.getDuplicateCompany(companyId);
		return count;
	}
	
	@PostMapping("saveWorkers")
	public Workers saveWorkersData(@RequestBody Workers worker) {
		Workers saveWorker = service.saveWorkersData(worker);
		return saveWorker;
	}
	
	@GetMapping("getWorkersList")
	public CompanyDetails getWorkersList(@RequestParam(defaultValue = "1") int page,
	        @RequestParam(defaultValue = "10") int size){
		CompanyDetails workersList = service.getWorkersList(page-1, size);
		return workersList;
	}
	
	@GetMapping("getWorkersById")
	public Optional<Workers> getWorkersById(@RequestParam long workerId){
		Optional<Workers> workersListById = service.getWorkersById(workerId);
		return workersListById;
	}
	
	@GetMapping("deleteWorkerById")
	public Map<String,String> deleteWorkerById(@RequestParam long workerId){
		Map<String,String> deletedRes = service.deleteWorkerById(workerId);
		return deletedRes;
	}
	
	@PostMapping("updateWorkers")
	public Map<String,String> updateWorkers(@RequestBody Workers worker) {
		Map<String,String> updatedRes = service.updateWorkers(worker);
		return updatedRes;
	}
	
	@PostMapping("saveCustomers")
	public Customers saveCustomersData(@RequestBody Customers customers) {
		Customers customer = service.saveCustomersData(customers);
		return customer;
	}
	
	@GetMapping("getCustomersList")
	public CompanyDetails getCustomersList(@RequestParam(defaultValue = "1") int page,
			@RequestParam(defaultValue = "10") int size){
		CompanyDetails customersList = service.getCustomersList(page-1, size);
		return customersList;
	}
	
	@GetMapping("getCustomerById")
	public  Optional<Customers> getCustomerById(@RequestParam long customerId){
		 Optional<Customers> customersById = service.getCustomerById(customerId);
		return customersById;
	}
	
	@GetMapping("deleteCustomerById")
	public Map<String,String> deleteCustomerById(@RequestParam long customerId){
		Map<String,String> deletedRes = service.deleteCustomerById(customerId);
		return deletedRes;
	}
	
	@PostMapping("updateCustomers")
	public Map<String,String> updateCustomers(@RequestBody Customers customers) {
		Map<String,String> cusRes = service.updateCustomers(customers);
		return cusRes;
	}
	
}
