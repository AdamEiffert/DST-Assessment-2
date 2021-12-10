library(data.table)
library(mlr)
library(tidyr)
library(dplyr)
library(R.utils)
library(assertr)

id <- "1gSgV0Fb8ejOS0AChbFTqw-CtNCvNuT3L" # google file ID
data<-read.csv(sprintf("https://docs.google.com/uc?id=%s&export=download", id))
df<-data.table(data)
head(df)

#'X' is repeated index, 'uid' is uninformative
df[,c('X','uid'):=NULL]
single_cols = vector()

uniq_cols = df[,lapply(.SD,uniqueN)]
uniq_cols


for (i in seq_along(uniq_cols)){
  if(uniq_cols[[i]]==1){
    single_cols<-append(single_cols,names(uniq_cols)[i])
  }
}

single_cols

#I would have looped over single_cols here to remove but R and I 
#have a hate-hate relationship so I'm doing it manually
df<-df[,c('local_orig','missed_bytes','tunnel_parents'):=NULL]
head(df)

#create a data.table of our features, removing our prediction target
features<-data.table(df)
features<-features[,c('malicious','atcktype'):=NULL]
head(features)
#create data.table of our prediction target
target<-data.table(df)
target<-target[,c('malicious')]
head(target)


ip_df <- data.table(features[,c('srcIP','dstIP')])
ip_df

#create a vector of ipv6 adddresses
src_ipv6<-vector()

for (ip in ip_df[,srcIP]){
  has_colon <- grepl(':',ip)
  
  if (has_colon){
    src_ipv6<-append(src_ipv6,ip)
  }
  
}

#find all the unique ipv6 addresses so we can study their form
u_src_ipv6=unique(src_ipv6)
head(u_src_ipv6)

#create a vector of ipv6 addresses that have '::' in them
src_double_colon<-vector()

for (u_ip in src_u_ipv6){
  if (grepl('::',u_ip)){
    src_double_colon<-append(src_double_colon,u_ip)
  }
}

src_double_colon

#for somewhat better readability of src_double_colon's form
for (i in src_double_colon){
  print(strsplit(i,'::'))
}

########## dstIP ##########
dst_ipv6<-vector()

for (ip in ip_df[,dstIP]){
  has_colon <- grepl(':',ip)
  
  if (has_colon){
    dst_ipv6<-append(dst_ipv6,ip)
  }
  
}

#find all the unique ipv6 addresses so we can study their form
dst_u_ipv6=unique(dst_ipv6)
head(dst_u_ipv6)

#create a vector of ipv6 addresses that have '::' in them
dst_double_colon<-vector()

for (u_ip in dst_u_ipv6){
  if (grepl('::',uip)){
    dst_double_colon<-append(dst_double_colon,u_ip)
  }
}

dst_double_colon

#for somewhat better readability of dst_double_colon's form
for (i in dst_double_colon){
  print(strsplit(i,'::'))
}

### ipv6 that have :: in them start with either fe80 or 2001
### if starting with fe80 the form is fe80::a1:a2:...:ak where k varies
### if starting with 2001 the form is 2001:a2:a3:a4::a8 so we always have 
### #### ':000:0000:0000:' as the 'missing' zeros



#we use what we learn from the ipv6 forms above to create a function
#that cleans up the ipv6 addresses so they are all in the form
#a1:a2:a3:...:a8
cleanIP <- function(ip) {
  ip<-as.character(ip)
  if(grepl('::',ip)){
    #special case
    if(ip=='::'){
      
      ip<-'0000:0000:0000:0000:0000:0000:0000:0000'
      
    }else {
      
      #all our IPv6 instances that have '::' within them are of the form
      #fe80::x, where x is some a1:a2:...:ak for k=[1:6]
      ip_split<-as.list(strsplit(ip,'::')[[1]])
      
      #this corresponds to a1:a2:...:ak mentioned above
      ip_sec_half<-ip_split[[2]]
      
      #ipv6 that start with 2 and contain :: follow the form 
      #a1:a2:a3:a4::a8, so 5-7 are 'missing'
      if (substring(ip,1,1)=='2'){
        
        missing_colons=3
        
        } else {
          #returns k mentioned above
          active_colons<-length(as.list(strsplit(ip_sec_half,':'))[[1]])
          #there are a total of 8 'sections' in an IPv6 address
          #including 'k' and 'fe80' we have m missing_colons below
          missing_colons=8-(active_colons+1)
        }
      
      #returns ':0000:0000:0000:' for m=3 for example
      zeros<-paste(c(replicate(missing_colons,':0000'),':'),collapse="")
      
      #putting all components together
      ip_clean<-paste(ip_split[[1]],zeros,ip_split[[2]],sep="")
      
      ip<-ip_clean
    }

  }
  return(ip)
}

#test_ip is just backup for ip_df 
test_ip<-data.table(ip_df)
test_ip

L = length(test_ip[,dstIP])

#create vectors for where ipv6 addresses with '::' in them appear
src_ind = vector()

#initially did a separate list for dst_ind but then realised the indices are exactly the same
#dst_ind = vector()

#loop over to append i to src_ind and dst_ind
####this is really slow, not sure if there's a faster way to do this that would save time
for (i in 1:L){
  sip=test_ip[,'srcIP'][i]
#  dip=test_ip[,'dstIP'][i]
  
  if (grepl(':',sip)){
    
    sip=as.character(sip)
    sip=cleanIP(sip)
    
    src_ind<-append(src_ind,i)
    test_ip[,'srcIP'][i]=sip
  }
  
#  if (grepl(':',dip)){
 #   dip=as.character(dip)
  #  dip=cleanIP(dip)
   # 
    #dst_ind<-append(dst_ind,i)
    #test_ip[,'dstIP'][i]=dip
    
  #}
  #just to keep track of how many loops have been done, can comment out or remove
  print(i)

}


#quick check to see if values have changed in test_ip[,srcIP] or not
suip = unique(test_ip[,srcIP])
duip = unique(test_ip[,dstIP])

print('----srcIP----')
suip6<-vector()
for (ip in suip){
  
  if (grepl(':',ip)){
    print(ip)
    suip6<-append(suip6,ip)
  }
}

print('----dstIP----')
duip6<-vector()
for (ip in duip){
  
  if (grepl(':',ip)){
    print(ip)
    duip6<-append(duip6,ip)
  }
}
#everything looks like it works fine

#we create a function that takes the 4 elements of ipv4 e.g. 
#ip_1=192, ip_2 = 168, ip_3=202, ip_4=24
#then each of those is converted to 8-bit binary and the 32 digits are then concatenated
#the same is done for ipv6 using 16-bit binary
IPBinary <- function(vector=test_ip[,'srcIP'],vec_ind=src_ind) {
  t<-data.table(vector)
  
  colnames(t)<-'t'
  
  #data.table made up of ipv6 addresses and corresponding index in our initial dataset
  t1<-data.table('ip'=t[vec_ind],'index'=vec_ind)
  #data.table made up of ipv4 addresses and corresponding index in our initial dataset
  t2<-data.table('ip'=t[-vec_ind],'index'=(1:L)[-vec_ind])
  
  #separate ipv6 into 8 columns
  t1_sep<-t1%>% separate(ip.t,c(as.character(1:8)))
  #separate ipv4 into 4 columns
  t2_sep<-t2%>% separate(ip.t,c(as.character(1:4)))
  
  #get all ip columns as a matrix
  m1 = as.matrix(t1_sep[,-'index'])
  #turn each hexadecimal to binary
  m1[] = R.utils::intToBin(strtoi(m1,base=16L))
  
  t1_comb<-data.table(m1)
  #concat all 16-bit binary columns together
  t1_conc<-col_concat(t1_comb, sep = "")
  #create data.table with the concatenated binaries and corresponding index
  t1_conc <- data.table('bin'=t1_conc, 'index'=t1[,'index'])
  colnames(t1_conc)<-c('bin','index') 
  
  #repeat for ipv4
  m2 = as.matrix(t2_sep[,-'index'])
  m2[] = R.utils::intToBin(strtoi(m2))
  t2_comb<-data.table(m2)
  t2_conc<-col_concat(t2_comb, sep = "")
  t2_conc <- data.table('bin'=t2_conc, 'index'=t2[,'index'])
  colnames(t2_conc)<-c('bin','index') 
  
  #create a dummy vector of length 200,000
  check_vec<-rep(1,L)
  check_vec
  
  #assign binary value to ith element of vector where i corresponds to appropriate index for ipv6
  for (i in seq_along(t1_conc[[1]])){
    #concatenated binary
    bin<-t1_conc[i][[1]]
    #corresponding index
    ind<-t1_conc[i][[2]]
    
    #value assignment
    check_vec[ind]<-bin
    
  }
  
  #repeat for ipv4
  for (i in seq_along(t2_conc[[1]])){
    
    bin<-t2_conc[i][[1]]
    ind<-t2_conc[i][[2]]
  
    check_vec[ind]<-bin
    print(paste(i,ind))
  }
  
  return (check_vec)
}  

final_features<-data.table(features)
final_features<-final_features[,c('srcIP','dstIP'):=NULL]
head(final_features)

final_features$srcIP_bin<-IPBinary()
final_features$dstIP_bin<-IPBinary(vector=test_ip[,'dstIP'])

head(final_features)