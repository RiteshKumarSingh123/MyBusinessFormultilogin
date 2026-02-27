package com.business.busi.customer.serviceimpl;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
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


@Service
public class CompanyUserSevice implements CompanyService {

	@Autowired
	private CompanyRepository repository;
	
	@Autowired
	private WorkersRepository workerRepo;
	
	@Autowired
	private CustomersRepository customerRepo;

	@Override
	public Company saveCompanyInfo(Company company) {
		Company saveResponse = repository.save(company);
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
		Pageable pageable = PageRequest.of(page, size);
//		List<Company> companyList = repository.findAll();
		Page<Company> companyPage = repository.findAll(pageable);
		List<Company> companyList = companyPage.getContent();
		CompanyDetails companyFilter = companyList.stream().map(a->{a.setCompanyName(a.getCompanyName().toUpperCase());return a;}).sorted(Comparator.comparing(Company::getCompanyId).reversed())
		.collect(Collectors.collectingAndThen(Collectors.toList(), detailsList->{
		CompanyDetails setDetails = new CompanyDetails();
		setDetails.setCompanyFilter(detailsList);
		setDetails.setCount(companyPage.getTotalElements());
		setDetails.setTotalPages(companyPage.getTotalPages());
		setDetails.setCurrentPage(companyPage.getPageable().getPageNumber()+1);
		return setDetails;
		}));
		
	    return   companyFilter;
	}
		
	@Override
	public CompanyDetails getCompanyDetailsList(int page, int size) {
		Pageable pageable = PageRequest.of(page, size);
//		List<Company> companyList = repository.findAll();
		Page<Company> companyPage = repository.findAll(pageable);
		List<Company> companyList = companyPage.getContent();
		CompanyDetails companyDetailsData = companyList.stream().map(a->{
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
		return companyDetailsData;
	}

	@Override
	public Optional<Company> getCompanyById(long companyId) {
		Optional<Company> dataById = repository.findById(companyId);
		Optional<Company> companyInfoById = dataById.stream().map(a->{a.setCompanyName(a.getCompanyName().toUpperCase());return a;}).findAny();
		return companyInfoById;
	}

	@Override
	public Map<String, String> deleteCompanyById(long companyId) {
		repository.deleteById(companyId);
		Map<String, String> res = new HashMap<String,String>();
		res.put("status", "data deleted successfully");
		return res;
	}

	@Override
	public Map<String, String> updateCompany(Company company) {
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
		Map<String,String> res = new HashMap<String,String>();
		res.put("status", "data updated successfully");
		return res;
	}

	@Override
	public Map<String, String> getDuplicateCompany(long companyId) {
	boolean exist = false;
	exist =	repository.existsById(companyId);
	Map<String,String> res = new HashMap<String,String>();
	if(exist) {
		res.put("status", "record exists");
	}else {
		res.put("status", "record doesn't exists");
	}
	return res; 

    }

	@Override
	public Workers saveWorkersData(Workers worker) {
		Workers saveResponse = workerRepo.save(worker);
		return saveResponse;
	}

	@Override
	public CompanyDetails getWorkersList(int page, int size) {
		Pageable pageable = PageRequest.of(page, size);
		Page<Workers> workersPage = workerRepo.findAll(pageable);
//		List<Workers> workersDataList = workerRepo.findAll();
		List<Workers> workersDataList = workersPage.getContent();
		CompanyDetails workerFilterList = workersDataList.stream()
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
		return workerFilterList;
	}

	@Override
	public Optional<Workers> getWorkersById(long workerId) {
		Optional<Workers> workersData = workerRepo.findById(workerId);
		Optional<Workers> workers = workersData.stream().map(a->{
			a.setWorkerName(a.getWorkerName().toUpperCase());
			a.setUnderWhichCompany(a.getUnderWhichCompany().toUpperCase());
			return a;
		}).findAny();
		return workers;
	}

	@Override
	public Map<String, String> deleteWorkerById(long workerId) {
		workerRepo.deleteById(workerId);
		Map<String,String> res = new HashMap<String,String>();
		res.put("status", "data deleted sucessfully");
		return res;
	}

	@Override
	public Map<String, String> updateWorkers(Workers worker) {
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
		Map<String,String> res = new HashMap<String,String>();
		res.put("status", "data updated sucessfully");
		return res;
	}

	@Override
	public Customers saveCustomersData(Customers customers) {
	 Customers saveCustomer = customerRepo.save(customers);
	 return saveCustomer;
	}

	@Override
	public CompanyDetails getCustomersList(int page , int size) {
		Pageable pageable = PageRequest.of(page, size);
		Page<Customers> customerPageable = customerRepo.findAll(pageable);
//	    List<Customers> customersList = customerRepo.findAll();
		List<Customers> customersList = customerPageable.getContent();
	    CompanyDetails details = customersList.stream().map(a->{a.setCustomerName(a.getCustomerName().toUpperCase());return a;})
	    		.sorted(Comparator.comparing(Customers::getCustomerId).reversed())
	    		.collect(Collectors.collectingAndThen(Collectors.toList(), customerListData->{
	    			CompanyDetails companyData = new CompanyDetails();
	    			companyData.setCustomersFilter(customerListData);
	    			companyData.setCount(customerPageable.getTotalElements());
	    			companyData.setTotalPages(customerPageable.getTotalPages());
	    			companyData.setCurrentPage(customerPageable.getPageable().getPageNumber()+1);
	    			return companyData;
	    		}));
		return details;
	}

	@Override
	public Optional<Customers> getCustomerById(long customerId) {
		 Optional<Customers> customerData = customerRepo.findById(customerId);
		 Optional<Customers> customersDataById = customerData.stream()
		 .map(a->{a.setCustomerName(a.getCustomerName().toUpperCase());return a;}).findAny();
		return customersDataById;
	}

	@Override
	public Map<String, String> deleteCustomerById(long customerId) {
		customerRepo.deleteById(customerId);
		Map<String, String> delRes = new HashMap<String,String>();
		delRes.put("status", "data deleted sucessfully");
		return delRes;
	}

	@Override
	public Map<String, String> updateCustomers(Customers customers) {
		Customers customerUpdate = new Customers();
		if(customers.getCustomerId()>0) {
			customerUpdate.setCustomerId(customers.getCustomerId());	
			customerUpdate.setCustomerAdress(customers.getCustomerAdress());
			customerUpdate.setCustomerAge(customers.getCustomerAge());
			customerUpdate.setCustomerName(customers.getCustomerName());
		}
		Customers resData = customerRepo.save(customerUpdate);
		Map<String, String> updateRes = new HashMap<String,String>();
		updateRes.put("status", "data updated sucessfully");
		return updateRes;
	}

}
