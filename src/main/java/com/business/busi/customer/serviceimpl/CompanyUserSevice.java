package com.business.busi.customer.serviceimpl;

import java.sql.SQLException;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import com.business.busi.customer.entity.Company;
import com.business.busi.customer.entity.Customers;
import com.business.busi.customer.entity.Workers;
import com.business.busi.customer.model.CompanyDetails;
import com.business.busi.customer.repository.CompanyRepository;
import com.business.busi.customer.repository.CustomersRepository;
import com.business.busi.customer.repository.WorkersRepository;
import com.business.busi.customer.service.CompanyService;
import com.business.busi.exception.MyBusinessProException;


@Service
public class CompanyUserSevice implements CompanyService {
	
	private static final Logger logger = LoggerFactory.getLogger(CompanyUserSevice.class);

	@Autowired
	private CompanyRepository repository;
	
	@Autowired
	private WorkersRepository workerRepo;
	
	@Autowired
	private CustomersRepository customerRepo;

	@Override
	public Company saveCompanyInfo(Company company) {
		Company saveResponse = null;
		try {
	    saveResponse = repository.save(company);
		}catch(DataAccessException  e) {
		 logger.error("error handling DataAccessException :->", e.getMessage());	
		 throw new MyBusinessProException("DataAccessException  error saveCompanyInfo ", e.getMessage());
		}catch(Exception e) {
		 logger.error("error handling Exception:->", e.getMessage());	
		 throw new MyBusinessProException("Exception error saveCompanyInfo ", e.getMessage());
		}
		return saveResponse;
	}

//	@Override
//	public CompanyDetails getCompanyList() {
//		List<Company> companyList = repository.findAll();
//		long count = companyList.stream().count();
//		List<Company> companyFilter = companyList.stream().map(a->{a.setCompanyName(a.getCompanyName().toUpperCase());return a;}).sorted(Comparator.comparing(Company::getCompanyId).reversed()).toList();
//		CompanyDetails setCompany = new CompanyDetails();
//		setCompany.setCount(count);
//		setCompany.setCompanyFilter(companyFilter);
//		return setCompany;
//	        
//		}
	
	@Override
	public CompanyDetails getCompanyList(int page, int size) {
		CompanyDetails companyFilter = null;
		try {
		Pageable pageable = PageRequest.of(page, size);
//		List<Company> companyList = repository.findAll();
		Page<Company> companyPage = repository.findAll(pageable);
		List<Company> companyList = companyPage.getContent();
	    companyFilter = companyList.stream().map(a->{a.setCompanyName(a.getCompanyName().toUpperCase());return a;}).sorted(Comparator.comparing(Company::getCompanyId).reversed())
		.collect(Collectors.collectingAndThen(Collectors.toList(), detailsList->{
		CompanyDetails setDetails = new CompanyDetails();
		setDetails.setCompanyFilter(detailsList);
		setDetails.setCount(companyPage.getTotalElements());
		setDetails.setTotalPages(companyPage.getTotalPages());
		setDetails.setCurrentPage(companyPage.getPageable().getPageNumber()+1);
		return setDetails;
		}));
		}catch(DataAccessException  e) {
		 logger.error("error handling DataAccessException :->", e.getMessage());	
		 throw new MyBusinessProException("DataAccessException  error getCompanyList ", e.getMessage());
		}catch(Exception e) {
		 logger.error("error handling Exception:->", e.getMessage());	
		 throw new MyBusinessProException("Exception error getCompanyList ", e.getMessage());
		}
	    return   companyFilter;
	}
		
	@Override
	public CompanyDetails getCompanyDetailsList(int page, int size) {
		CompanyDetails companyDetailsData = null;
		try {
		Pageable pageable = PageRequest.of(page, size);
//		List<Company> companyList = repository.findAll();
		Page<Company> companyPage = repository.findAll(pageable);
		List<Company> companyList = companyPage.getContent();
	    companyDetailsData = companyList.stream().map(a->{
			a.setCompanyName(a.getCompanyName().toUpperCase());
			a.setOwnerName(a.getOwnerName().toUpperCase());
			a.setCompanyProducts(a.getCompanyProducts().toUpperCase());
			return a;
		})
		.collect(Collectors.collectingAndThen(Collectors.toList(), listOfCompany->{
		CompanyDetails details = new CompanyDetails();
		details.setCompanyFilter(listOfCompany);
		details.setCount(companyPage.getTotalElements());
		details.setTotalPages(companyPage.getTotalPages());
		details.setCurrentPage(companyPage.getPageable().getPageNumber()+1);
		return details;
		}));
		}catch(DataAccessException  e) {
	     logger.error("error handling DataAccessException :->", e.getMessage());	
	     throw new MyBusinessProException("DataAccessException  error getCompanyDetailsList ", e.getMessage());
		}catch(Exception e) {
		 logger.error("error handling Exception:->", e.getMessage());	
		 throw new MyBusinessProException("Exception error getCompanyDetailsList ", e.getMessage());
		}
		return companyDetailsData;
	}

	@Override
	public Optional<Company> getCompanyById(long companyId) {
		Optional<Company> companyInfoById = null;
		try {
		Optional<Company> dataById = repository.findById(companyId);
	    companyInfoById = dataById.stream().map(a->{a.setCompanyName(a.getCompanyName().toUpperCase());return a;}).findAny();
		}catch(DataAccessException  e) {
		  logger.error("error handling DataAccessException :->", e.getMessage());	
		  throw new MyBusinessProException("DataAccessException  error getCompanyById ", e.getMessage());
	    }catch(Exception e) {
		  logger.error("error handling Exception:->", e.getMessage());	
		  throw new MyBusinessProException("Exception error getCompanyById ", e.getMessage());
		}
		return companyInfoById;
	}

	@Override
	public Map<String, String> deleteCompanyById(long companyId) {
		Map<String, String> res = new HashMap<String,String>();
		try {
		repository.deleteById(companyId);
		res.put("status", "data deleted successfully");
		}catch(DataAccessException  e) {
			logger.error("error handling DataAccessException :->", e.getMessage());	
			throw new MyBusinessProException("DataAccessException  error deleteCompanyById ", e.getMessage());
		}catch(Exception e) {
			logger.error("error handling Exception:->", e.getMessage());	
			throw new MyBusinessProException("Exception error deleteCompanyById ", e.getMessage());
		}
		return res;
	}

	@Override
	public Map<String, String> updateCompany(Company company) {
		Map<String,String> res = new HashMap<String,String>();
		try {
		Company companyData = null;
		if(company.getCompanyId()>0) {
			companyData = new Company();
			companyData.setCompanyId(company.getCompanyId());
			companyData.setCompanyAddress(company.getCompanyAddress());
			companyData.setCompanyName(company.getCompanyName());
			companyData.setCompanyProducts(company.getCompanyProducts());
			companyData.setCompanyTotalMembers(company.getCompanyTotalMembers());
			companyData.setOwnerName(company.getOwnerName());
			companyData.setWorkingHours(company.getWorkingHours());
		}
		Company setCompany = repository.save(companyData);
		res.put("status", "data updated successfully");
		}catch(DataAccessException  e) {
		  logger.error("error handling DataAccessException :->", e.getMessage());	
		  throw new MyBusinessProException("DataAccessException  error updateCompany ", e.getMessage());
		}catch(Exception e) {
		  logger.error("error handling Exception:->", e.getMessage());	
		  throw new MyBusinessProException("Exception error updateCompany ", e.getMessage());
		}
		return res;
	}

	@Override
	public Map<String, String> getDuplicateCompany(long companyId) {
	Map<String,String> res = new HashMap<String,String>();
	try {
	boolean exist = false;
	exist =	repository.existsById(companyId);
	
	if(exist) {
		res.put("status", "record exists");
	}else {
		res.put("status", "record doesn't exists");
	}
	}catch(DataAccessException  e) {
		 logger.error("error handling DataAccessException :->", e.getMessage());	
		 throw new MyBusinessProException("DataAccessException  error getDuplicateCompany ", e.getMessage());
	}catch(Exception e) {
		 logger.error("error handling Exception:->", e.getMessage());	
		 throw new MyBusinessProException("Exception error getDuplicateCompany ", e.getMessage());
	}
	return res; 

    }

	@Override
	public Workers saveWorkersData(Workers worker) {
		Workers saveResponse = null;
		try {
	    saveResponse = workerRepo.save(worker);
		}catch(DataAccessException  e) {
		 logger.error("error handling DataAccessException :->", e.getMessage());	
		 throw new MyBusinessProException("DataAccessException  error saveWorkersData ", e.getMessage());
		}catch(Exception e) {
		 logger.error("error handling Exception:->", e.getMessage());	
		 throw new MyBusinessProException("Exception error saveWorkersData ", e.getMessage());
		}
		return saveResponse;
	}

	@Override
	public CompanyDetails getWorkersList(int page, int size) {
		CompanyDetails workerFilterList = null;
		try {
		Pageable pageable = PageRequest.of(page, size);
		Page<Workers> workersPage = workerRepo.findAll(pageable);
//		List<Workers> workersDataList = workerRepo.findAll();
		List<Workers> workersDataList = workersPage.getContent();
	    workerFilterList = workersDataList.stream()
				.map(a->{a.setWorkerName(a.getWorkerName().toUpperCase());
				a.setUnderWhichCompany(a.getUnderWhichCompany().toUpperCase());        
				return a;})
				.sorted(Comparator.comparing(Workers::getWorkerId).reversed())
				.collect(Collectors.collectingAndThen(Collectors.toList(), listOfWorkers->{
				CompanyDetails details = new CompanyDetails();	
				details.setWorkersFilter(listOfWorkers);
				details.setCount(workersPage.getTotalElements());
				details.setTotalPages(workersPage.getTotalPages());
				details.setCurrentPage(workersPage.getPageable().getPageNumber()+1);
				return details;
				}));
		}catch(DataAccessException  e) {
		 logger.error("error handling DataAccessException :->", e.getMessage());	
		 throw new MyBusinessProException("DataAccessException  error getWorkersList ", e.getMessage());
		}catch(Exception e) {
		 logger.error("error handling Exception:->", e.getMessage());	
		 throw new MyBusinessProException("Exception error getWorkersList ", e.getMessage());
		}
		return workerFilterList;
	}

	@Override
	public Optional<Workers> getWorkersById(long workerId) {
		Optional<Workers> workers = null;
		try {
		Optional<Workers> workersData = workerRepo.findById(workerId);
	    workers = workersData.stream().map(a->{
			a.setWorkerName(a.getWorkerName().toUpperCase());
			a.setUnderWhichCompany(a.getUnderWhichCompany().toUpperCase());
			return a;
		}).findAny();
		}catch(DataAccessException  e) {
			 logger.error("error handling DataAccessException :->", e.getMessage());	
			 throw new MyBusinessProException("DataAccessException  error getWorkersById ", e.getMessage());
		}catch(Exception e) {
			 logger.error("error handling Exception:->", e.getMessage());	
			 throw new MyBusinessProException("Exception error getWorkersById ", e.getMessage());
		}
		return workers;
	}

	@Override
	public Map<String, String> deleteWorkerById(long workerId) {
		Map<String,String> res = new HashMap<String,String>();
		try {
		workerRepo.deleteById(workerId);
		res.put("status", "data deleted sucessfully");
		}catch(DataAccessException  e) {
			 logger.error("error handling DataAccessException :->", e.getMessage());	
			 throw new MyBusinessProException("DataAccessException  error deleteWorkerById ", e.getMessage());
		}catch(Exception e) {
			 logger.error("error handling Exception:->", e.getMessage());	
			 throw new MyBusinessProException("Exception error deleteWorkerById ", e.getMessage());
		}
		return res;
	}

	@Override
	public Map<String, String> updateWorkers(Workers worker) {
		Map<String,String> res = new HashMap<String,String>();
		try {
		Workers workerRes = new Workers();
		if(worker.getWorkerId()>0) {
		workerRes.setWorkerId(worker.getWorkerId());
		workerRes.setAddress(worker.getAddress());
		workerRes.setUnderWhichCompany(worker.getUnderWhichCompany());
		workerRes.setWorkerName(worker.getWorkerName());
		workerRes.setWorkerPosition(worker.getWorkerPosition());
		workerRes.setDate(worker.getDate());
		}
		Workers workerdata = workerRepo.save(workerRes);
		res.put("status", "data updated sucessfully");
		}catch(DataAccessException  e) {
			 logger.error("error handling DataAccessException :->", e.getMessage());	
			 throw new MyBusinessProException("DataAccessException  error updateWorkers ", e.getMessage());
		}catch(Exception e) {
			 logger.error("error handling Exception:->", e.getMessage());	
			 throw new MyBusinessProException("Exception error updateWorkers ", e.getMessage());
		}
		return res;
	}

	@Override
	public Customers saveCustomersData(Customers customers) {
	 Customers saveCustomer = null;
	 try {
	 saveCustomer = customerRepo.save(customers);
	 }catch(DataAccessException  e) {
		 logger.error("error handling DataAccessException :->", e.getMessage());	
		 throw new MyBusinessProException("DataAccessException  error saveCustomersData ", e.getMessage());
	 }catch(Exception e) {
		 logger.error("error handling Exception:->", e.getMessage());	
		 throw new MyBusinessProException("Exception error saveCustomersData ", e.getMessage());
	 }
	 return saveCustomer;
	}

	@Override
	public CompanyDetails getCustomersList(int page , int size) {
		CompanyDetails details = null;
		try {
		Pageable pageable = PageRequest.of(page, size);
		Page<Customers> customerPageable = customerRepo.findAll(pageable);
//	    List<Customers> customersList = customerRepo.findAll();
		List<Customers> customersList = customerPageable.getContent();
	    details = customersList.stream().map(a->{a.setCustomerName(a.getCustomerName().toUpperCase());return a;})
	    		.sorted(Comparator.comparing(Customers::getCustomerId).reversed())
	    		.collect(Collectors.collectingAndThen(Collectors.toList(), customerListData->{
	    			CompanyDetails companyData = new CompanyDetails();
	    			companyData.setCustomersFilter(customerListData);
	    			companyData.setCount(customerPageable.getTotalElements());
	    			companyData.setTotalPages(customerPageable.getTotalPages());
	    			companyData.setCurrentPage(customerPageable.getPageable().getPageNumber()+1);
	    			return companyData;
	    		}));
		}catch(DataAccessException  e) {
		 logger.error("error handling DataAccessException :->", e.getMessage());	
		 throw new MyBusinessProException("DataAccessException  error getCustomersList ", e.getMessage());
		}catch(Exception e) {
		 logger.error("error handling Exception:->", e.getMessage());	
		 throw new MyBusinessProException("Exception error getCustomersList ", e.getMessage());
		}
		return details;
	}

	@Override
	public Optional<Customers> getCustomerById(long customerId) {
		Optional<Customers> customersDataById = null;
		try {
		 Optional<Customers> customerData = customerRepo.findById(customerId);
		 customersDataById = customerData.stream()
		 .map(a->{a.setCustomerName(a.getCustomerName().toUpperCase());return a;}).findAny();
		}catch(DataAccessException  e) {
		 logger.error("error handling DataAccessException :->", e.getMessage());	
		 throw new MyBusinessProException("DataAccessException  error getCustomerById ", e.getMessage());
		}catch(Exception e) {
		 logger.error("error handling Exception:->", e.getMessage());	
		 throw new MyBusinessProException("Exception error getCustomerById ", e.getMessage());
		}
		return customersDataById;
	}

	@Override
	public Map<String, String> deleteCustomerById(long customerId) {
		Map<String, String> delRes = new HashMap<String,String>();
		try {
		customerRepo.deleteById(customerId);
		delRes.put("status", "data deleted sucessfully");
		}catch(DataAccessException  e) {
		 logger.error("error handling DataAccessException :->", e.getMessage());	
		 throw new MyBusinessProException("DataAccessException  error deleteCustomerById ", e.getMessage());
		}catch(Exception e) {
		 logger.error("error handling Exception:->", e.getMessage());	
		 throw new MyBusinessProException("Exception error deleteCustomerById ", e.getMessage());
		}
		return delRes;
	}

	@Override
	public Map<String, String> updateCustomers(Customers customers) {
		Map<String, String> updateRes = new HashMap<String,String>();
		try {
		Customers customerUpdate = new Customers();
		if(customers.getCustomerId()>0) {
			customerUpdate.setCustomerId(customers.getCustomerId());	
			customerUpdate.setCustomerAdress(customers.getCustomerAdress());
			customerUpdate.setCustomerAge(customers.getCustomerAge());
			customerUpdate.setCustomerName(customers.getCustomerName());
		}
		Customers resData = customerRepo.save(customerUpdate);
		
		updateRes.put("status", "data updated sucessfully");
		}catch(DataAccessException  e) {
		 logger.error("error handling DataAccessException :->", e.getMessage());	
		 throw new MyBusinessProException("DataAccessException  error updateCustomers ", e.getMessage());
		}catch(Exception e) {
		 logger.error("error handling Exception:->", e.getMessage());	
		 throw new MyBusinessProException("Exception error updateCustomers ", e.getMessage());
		}
		return updateRes;
	}

}
