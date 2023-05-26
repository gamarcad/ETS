# Formal Verification of Applause using ProVerif

#### Description of the ProVerif files contained in this repository
This folder contains ProVerif files corresponding to each security property we are considering. It contains 2 folders:
- `Privacy` : contains privacy properties (Anonymity)
- `Trace Properties` : contains authentication, secrecy, double-refund, double-validate and double-transfer properties. We refer to our paper for a description of each security property. 

#### Running the files and expected results
The security properties can be verified by running the following command. 
```
proverif <property>.pv
```
where `<property>` can be `Anonymity_User1`, `Anonymity_User2`, `Double_Refund`, `Double_Transfert`, `Double_Validate`, `Secrecy_of_Ticket`, `Authentication_User_And_D`, `Authentication_User_And_V` and `Authentication_Users_And_T`.


