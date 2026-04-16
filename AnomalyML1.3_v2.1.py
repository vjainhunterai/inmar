#!/usr/bin/env python
# coding: utf-8

# In[51]:


# In[22]:


import pandas as pd
import os
import numpy as np
from datetime import datetime
from itertools import count
from tqdm import tqdm
import Levenshtein
import re
import ast
import networkx as nx
from sqlalchemy import create_engine, text
import urllib
import sys
tqdm.pandas()
a=pd.DataFrame()
from itertools import combinations
import gc


# In[20]:


def ML1():
    import pandas as pd
    from cryptography.fernet import Fernet
    import os
    import sys
    try:
        env_local= os.getenv("ENV", "prod")
    except Exception as e:
        print(f"{e}")
    def readEncryptedConfig(excelFilePath,env):
        """
        Reads the encrypted configuration from the Excel file.

        Args:
            excel_file_path (str): The path to the Excel file.

        Returns:
            dict: A dictionary containing the decrypted configuration.
        """
        def decryptData(data, keyDirectory):

            scKey = open(keyDirectory, 'rb').read()
            cipherSuite = Fernet(scKey)
            if isinstance(data, str):
                return cipherSuite.decrypt(data.encode()).decode()
            else:
                return data
        # Read paths from Excel file
        pathsDf1 = pd.read_excel(excelFilePath)
        pathsDf = pathsDf1[pathsDf1['Env'] == env]
        pathsDict = pathsDf.set_index('Key_name')['Path'].to_dict()

        # Read the encryption key
        keyPath = pathsDict['key_path']
        encryptedFile = pathsDict['encrypted_file']

        # Read the encryption key
        scKey = open(keyPath, 'rb').read()
        cipherSuite = Fernet(scKey)

        # Read the encrypted file
        df = pd.read_csv(encryptedFile)

        # Decrypt the data
        df_decrypted = df.applymap(lambda x: decryptData(str(x), keyPath))
        df = pd.DataFrame(df_decrypted)

        # Extract configuration
        config = {
             'host': str(df.at[0, 'host']),
             'database': str(df.at[0, 'database']),
             'user': str(df.at[0, 'user']),
             'password': str(df.at[0, 'password']),
             'port': 3306
         }

        return config

    def getDataFromDatabase_temorary(table_name):
        a = readEncryptedConfig(r'/home/ubuntu/anomaly_data_pipeline/Data_Engg_Data_Science_Pre_Prod/Anomaly/Config/Paths.xls', env_local)
        user = a['user']
        pwd = a['password']
        password = urllib.parse.quote_plus(pwd)
        ip = a['host']
        schema = "anomaly"
        engine = create_engine('mysql+mysqlconnector://{0}:{1}@{2}/{3}'.format(user, password, ip, schema))
        query = f"SELECT * FROM anomaly.{table_name}"
        with engine.connect() as conn:
            df = pd.read_sql(query, conn)
        return df
    def uploadOutput_temorary(output, table_name):
        a = readEncryptedConfig(r'/home/ubuntu/anomaly_data_pipeline/Data_Engg_Data_Science_Pre_Prod/Anomaly/Config/Paths.xls', env_local)
        user = a['user']
        pwd = a['password']
        password = urllib.parse.quote_plus(pwd)
        ip = a['host']
        schema = "anomaly"
        engine = create_engine('mysql+mysqlconnector://{0}:{1}@{2}/{3}'.format(user, password, ip, schema))
        output.to_sql(table_name, con = engine, if_exists='replace', index=False)


    def extract_digits(text):
        if pd.isna(text):
            return ''
        text = str(text)
        match = re.search(r'\d.*\d', text)
        return match.group(0) if match else ''


    def clean_price(value):
        value = value.replace(' ','')
        value = re.sub(r'(\d),(?=\d{3}(\D|$))', r'\1', value)
        value = re.sub(r'(\d)\.(?=\d{3}(\D|$))', r'\1', value)
        value = re.sub(r'(\d),(?=\d{1,2}(\D|$))', r'\1.', value)
        value = value.replace(',','')
        value = value.replace('$','')
        parts = value.split('.')
        if len(parts) > 2:
            value = parts[0] + ''.join(parts[1:-1]) + '.' + parts[-1]
        try:
            cleaned_value = float(value)
        except ValueError:
            cleaned_value = value
        return cleaned_value

    def process_date_and_assign_group(group, ndays):
        global group_id_counter
        group = group.sort_values('Inv_Date')
        group['Date_Diff'] = group['Inv_Date'].diff().dt.days.fillna(0).abs()
        group['New_Group'] = (group['Date_Diff'] > ndays).cumsum() + group_id_counter
        group['Group_ID'] = group['New_Group']
        group_id_counter += group['Group_ID'].nunique()
        return group

    def assign_matching_indices(group, ndays):
        if len(group)<2:
            group['matching_index'] = [[] for _ in range(len(group))]
            return group
        matching_indices = {}
        for idx, row in group.iterrows():
            matches = group[(group['Inv_Date'] - row['Inv_Date']).dt.days.abs() <= ndays]
            if len(matches) > 1:
                matching_indices[idx] = list(matches['Index_row'].values)
            else:
                matching_indices[idx] = []
        group['matching_index'] = group.index.map(matching_indices)
        return group
    def remove_matching_chq_no(group):
        group['matching_index'] = group['matching_index'].apply(lambda x: eval(x) if isinstance(x, str) else x)

        for idx, row in group.iterrows():
            current_index = row['Index_row']
            current_chq_no = row['Chq_No']

            matching_indices = row['matching_index']

            filtered_indices = [
                match_idx
                for match_idx in matching_indices
                if group.loc[group['Index_row'] == match_idx, 'Chq_No'].iloc[0] != current_chq_no
            ]

            group.at[idx, 'matching_index'] = filtered_indices

        return group
    def filter_by_levenshtein_distance(group):
        group['matching_index'] = group['matching_index'].apply(lambda x: eval(x) if isinstance(x, str) else x)
        for idx, row in group.iterrows():
            current_index = row['Index_row']
            current_invoice = row['Suppliers_Invoice_Number']

            matching_indices = row['matching_index']

            filtered_indices = [
                match_idx
                for match_idx in matching_indices
                if Levenshtein.distance(current_invoice,
                                         group.loc[group['Index_row'] == match_idx, 'Suppliers_Invoice_Number'].iloc[0]) <= 2
            ]

            group.at[idx, 'matching_index'] = filtered_indices

        return group
    def filter_by_numeric_difference(group):
        group['matching_index'] = group['matching_index'].apply(lambda x: eval(x) if isinstance(x, str) else x)

        for idx, row in group.iterrows():
            current_index = row['Index_row']
            current_number = int(row['Suppliers_Invoice_Number'])

            matching_indices = row['matching_index']
            filtered_indices = [
                match_idx
                for match_idx in matching_indices
                if abs(current_number - int(group.loc[group['Index_row'] == match_idx, 'Suppliers_Invoice_Number'].iloc[0])) == 0 \
       or abs(current_number - int(group.loc[group['Index_row'] == match_idx, 'Suppliers_Invoice_Number'].iloc[0])) > 5
            ]

            group.at[idx, 'matching_index'] = filtered_indices

        return group



    def getDataFromDatabase():
        a = readEncryptedConfig(r'/home/ubuntu/anomaly_data_pipeline/Data_Engg_Data_Science_Pre_Prod/Anomaly/Config/Paths.xls', env_local)
        user = a['user']
        pwd = a['password']
        password = urllib.parse.quote_plus(pwd)
        ip = a['host']
        schema = "l1_t0004_db"
        engine = create_engine('mysql+mysqlconnector://{0}:{1}@{2}/{3}'.format(user, password, ip, schema))
        query = "SELECT * FROM l1_t0004_db.temp_ap_inv"  #(source data)
        with engine.connect() as conn:
            df = pd.read_sql(query, conn)
        return df

    combined = getDataFromDatabase()
    print(combined['EXTENDED_AMOUNT'].unique())
    target = ['seq_no' ,'Supplier_Invoice', 'Invoice_Number' ,'Company', 'Invoice_Status',
     'Intercompany', 'Direct_Intercompany' ,'Supplier' ,'Supplier_ID',
     'Default_Payment_Terms' ,'Default_Payment_Type' ,'Suppliers_Invoice_Number',
     'Created_On' ,'Invoice_Date', 'Invoice_Received_Date',
     'Invoice_Accounting_Date', 'Memo', 'Discount_Date' ,'Due_Date',
     'Invoice_Amount', 'Invoice_Status1', 'Balance_Due' ,'Currency',
     'Is_On_Hold____Blank__if_No_and__Yes__if_Yes', 'Adjustment',
     'Adjustment_Reason' ,'Procurement_Related' ,'Purchase_Orders',
     'External_PO_Number' , 'Invoice_Created_By' ,'Payment_Amount',
     'Payment_Handling_Instruction', 'Supplier_Invoice_Reference_ID',
     'Check_Number' ,'Cost_Center' ,'Location' ,'Site' ,'Line_Description',
     'Approval_Date' ,'Payment_Type', 'Settlement_Run_Number', 'Is_On_Hold',
     'Supplier_Document_Received', 'Quantity' ,'Unit_of_Measure' ,'Unit_Cost',
     'Extended_Amount' ,'Document_Link' ,'Payment_Date',
     'Document_Payment_Status', 'Payment_Status', 'Project' ,'Grant' ,'Gift',
     'Line_Company', 'Payee_Alternate_Names', 'External_System_ID_Reference']
    rename = ['SEQ_NO' ,'SUPPLIER_INVOICE' ,'INVOICE_NUMBER' ,'COMPANY' ,'INVOICE_STATUS',
     'INTERCOMPANY' ,'DIRECT_INTERCOMPANY', 'SUPPLIER' ,'SUPPLIER_ID',
     'DEFAULT_PAYMENT_TERMS' ,'DEFAULT_PAYMENT_TYPE' ,'SUPPLIERS_INVOICE_NUMBER',
     'CREATED_ON', 'INVOICE_DATE' ,'INVOICE_RECEIVED_DATE',
     'INVOICE_ACCOUNTING_DATE', 'MEMO' ,'DISCOUNT_DATE' ,'DUE_DATE',
     'INVOICE_AMOUNT' ,'INVOICE_STATUS1' ,'BALANCE_DUE' ,'CURRENCY',
     'IS_ON_HOLD_BLANK_IF_NO_AND_YES_IF_YES', 'ADJUSTMENT' ,'ADJUSTMENT_REASON',
     'PROCUREMENT_RELATED' ,'PURCHASE_ORDERS', 'EXTERNAL_PO_NUMBER',
     'INVOICE_CREATED_BY' ,'PAYMENT_AMOUNT', 'PAYMENT_HANDLING_INSTRUCTION',
     'SUPPLIER_INVOICE_REFERENCE_ID', 'CHECK_NUMBER' ,'COST_CENTER' ,'LOCATION',
     'SITE' ,'LINE_DESCRIPTION' ,'APPROVAL_DATE', 'PAYMENT_TYPE',
     'SETTLEMENT_RUN_NUMBER', 'IS_ON_HOLD' ,'SUPPLIER_DOCUMENT_RECEIVED',
     'QUANTITY' ,'UNIT_OF_MEASURE' ,'UNIT_COST', 'EXTENDED_AMOUNT',
     'DOCUMENT_LINK' ,'PAYMENT_DATE' ,'DOCUMENT_PAYMENT_STATUS' ,'PAYMENT_STATUS',
     'PROJECT', 'GRANT' ,'GIFT' ,'LINE_COMPANY' ,'PAYEE_ALTERNATE_NAMES',
     'EXTERNAL_SYSTEM_ID_REFERENCE']
    rename_dict = dict(zip(rename, target))
    combined.rename(columns= lambda x: rename_dict[x] if x in rename_dict else x, inplace=True)
    print(combined['Extended_Amount'].unique())
    combined.columns

    def getDataFromDatabase():
        a = readEncryptedConfig(r'/home/ubuntu/anomaly_data_pipeline/Data_Engg_Data_Science_Pre_Prod/Anomaly/Config/Paths.xls', env_local)
        user = a['user']
        pwd = a['password']
        password = urllib.parse.quote_plus(pwd)
        ip = a['host']
        schema = "l3_dm_db"
        engine = create_engine('mysql+mysqlconnector://{0}:{1}@{2}/{3}'.format(user, password, ip, schema))
        query = "SELECT * FROM l3_dm_db.dim_vendor"
        with engine.connect() as conn:
            df = pd.read_sql(query, conn)
        return df
    vendor_name = getDataFromDatabase()

    combined = combined.merge(vendor_name[['VENDOR_NAME','VENDOR_NAME_ALIAS']], left_on= 'Supplier', right_on = 'VENDOR_NAME', how='left')
    combined.drop(columns=['VENDOR_NAME'], inplace=True)


    combined = combined.reset_index(drop=False)
    combined.rename(columns={'index': 'Index_row'}, inplace=True)
    original_full_dataset_reserve_copy = combined.copy()
    print(datetime.now().strftime("%H:%M:%S"))
    rename_mapping = {
        'Check_Number': 'Chq_No',
        'Extended_Amount': 'Pay_Amount',
        'Invoice_Date': 'Inv_Date',
        'Invoice_Number': 'Inv_No',
        'Line_Description': 'Item_Desc',
        'Supplier': 'Supp_No',
        "Inv_No_supplier": 'Suppliers_Invoice_Number',

    }
    combined = combined.rename(columns=rename_mapping)
    print(combined.shape)
    print(combined.columns)

    combined = combined[combined['Payment_Amount'] >= 0]
    combined = combined[combined['Invoice_Amount'] >= 0]
    combined = combined[combined['Pay_Amount'] >= 0]





    combined['Suppliers_Invoice_Number_Semen_Old_For_Recovery'] = combined['Suppliers_Invoice_Number']
    
    combined['Suppliers_Invoice_Number'] = (combined['Suppliers_Invoice_Number'].astype(str).apply(lambda x: ''.join(filter(str.isdigit, x)).lstrip('0') or '0'))
    combined = combined.dropna(subset=['Payment_Amount', 'Invoice_Amount'])
    #display(combined[['Payment_Amount', 'Invoice_Amount','Suppliers_Invoice_Number']])
    flag_check_number = 0
    if len(combined) > 3 and combined['Chq_No'].nunique() <= 3:
        flag_check_number = 1
        combined['Chq_No_Old'] = combined['Chq_No']
        combined['Chq_No'] = range(1, len(combined) + 1)
    combined = combined.drop_duplicates(subset=['seq_no'])
    combined['Inv_Date'] = pd.to_datetime(combined['Inv_Date'], format="mixed", errors = 'coerce')
    combined=combined.dropna(subset=['Inv_Date'])
    print(f"WRONG DATES: {len(combined[combined['Inv_Date'].isna()])}")
    print(combined.shape)
    print(datetime.now().strftime("%H:%M:%S"))
    combined_reserve_copy = combined.copy()
    #uploadOutput_temorary(combined_reserve_copy, 'random1')
    gc.collect()
    del original_full_dataset_reserve_copy
    global group_id_counter
    gc.collect()


    print("rulebased8")
    rulebased8 = pd.DataFrame()
    try:
        df = combined_reserve_copy.copy()
        print(datetime.now().strftime("%H:%M:%S"))

        pair_id_counter = count(1)
        df['Group_ID'] = (
             df[['Inv_Date','VENDOR_NAME_ALIAS',  'Invoice_Amount']]
            .astype(str)
            .agg('-'.join, axis=1)
            .rank(method='dense').astype(int)
        )

        group_id_counter = count(1)

        tqdm.pandas()
        def check_group(group):
            if len(group)>2 and (group['Pay_Amount']==group['Invoice_Amount']).any():
                filt_group = group[group['Pay_Amount'] != group['Invoice_Amount']]
                if len(filt_group)>0:
                    total_pay=filt_group['Pay_Amount'].sum()
                    total_invoice=group['Invoice_Amount'].max()
                    if isinstance(total_pay, (int, float)) and isinstance(total_invoice, (int, float)):
                        if total_pay>0 and total_invoice>0:
                            if abs(total_invoice-total_pay)/total_invoice <= 0.01:
                                group['Flag'] = 1
                            else:
                                group['Flag'] = 0
                        else:
                            group['Flag'] = 0
                    else:
                        group['Flag'] = 0
            else:
                group['Flag']=0
            return group
        df = df.groupby('Group_ID').progress_apply(check_group)

        rulebased8=df[df['Flag']==1]
        df = df.drop(columns=['Flag'])
        if flag_check_number == 1:
            rulebased8['Chq_No'] = rulebased8['Chq_No_Old']
            rulebased8 = rulebased8.drop(columns=['Chq_No_Old'])
        #uploadOutput_temorary(rulebased8, 'random3')
        print(datetime.now().strftime("%H:%M:%S"))
        print(f"rulebased8 - {rulebased8.shape}")
    except Exception as e:
        print(f"{e}")

    gc.collect()
    print("rulebased10")
    rulebased10 = pd.DataFrame()
    try:
        df = combined_reserve_copy.copy()
        print(datetime.now().strftime("%H:%M:%S"))
        pair_id_counter = count(1)
        df['Group_ID'] = (
         df[['Inv_Date','VENDOR_NAME_ALIAS',  'Invoice_Amount']]
            .astype(str)
            .agg('-'.join, axis=1)
            .rank(method='dense').astype(int)
        )

        group_id_counter = count(1)
        tqdm.pandas()

        def find_combinations(s_i, t_s):
            result = []
            for r in range(1, len(s_i) +1):
                for comb in combinations(s_i, r):
                    if sum(comb) == t_s:
                        result.append(comb)
            return result


        def check_group(group):
            group = group[group['Pay_Amount'] != group['Invoice_Amount']]
            if len(group)>0:
                seen1 = set()
                for a in group['Suppliers_Invoice_Number'].unique():
                    grouped_local = group[group['Suppliers_Invoice_Number']==a]
                    if tuple(grouped_local['Pay_Amount'].sort_values().tolist()) not in seen1:
                        seen1.add(tuple(grouped_local['Pay_Amount'].sort_values().tolist()))
                    else:
                        group = group[group['Suppliers_Invoice_Number']!=a]
                i_a = group['Invoice_Amount'].iloc[0]
                s_i = group.groupby('Suppliers_Invoice_Number')['Pay_Amount'].sum().reset_index()
                try:
                    combinations_result = find_combinations(s_i['Pay_Amount'].tolist(), i_a)
                except:
                    combinations_result = []
                if len(combinations_result) <2:
                    group['Flag']=0
                    return group
                valid_rows=set()
                for comb in combinations_result:
                    for invoice in comb:
                        valid_rows.update(s_i[s_i['Pay_Amount']==invoice].index)
                valid_rows = list(valid_rows)
                group_filtered = group[group['Suppliers_Invoice_Number'].isin(s_i.loc[valid_rows, 'Suppliers_Invoice_Number'])]
                if len(group_filtered) >0:
                    t_p = group_filtered['Pay_Amount'].sum()
                    t_i = 2*group_filtered.iloc[0]['Invoice_Amount']
                    if abs(t_i - t_p)/t_i <= 0.02:
                        group_filtered['Flag'] = 1
                    else:
                        group_filtered['Flag']=0
                else:
                    group_filtered['Flag']=0
                return group_filtered
            else:
                group['Flag']=0
                return group
        df = df.groupby('Group_ID').progress_apply(check_group)

        rulebased10=df[df['Flag']==1]
        df = df.drop(columns=['Flag'])
        if flag_check_number == 1:
            rulebased10['Chq_No'] = rulebased10['Chq_No_Old']
            rulebased10 = rulebased10.drop(columns=['Chq_No_Old'])
        #uploadOutput_temorary(rulebased10, 'random4')
        print(datetime.now().strftime("%H:%M:%S"))
        print(f"rulebased10 - {rulebased10.shape}")
    except Exception as e:
        print(f"{e}")

    gc.collect()


    def getDataFromDatabase_temorary(table_name):
        a = readEncryptedConfig(r'/home/ubuntu/anomaly_data_pipeline/Data_Engg_Data_Science_Pre_Prod/Anomaly/Config/Paths.xls', env_local)
        user = a['user']
        pwd = a['password']
        password = urllib.parse.quote_plus(pwd)
        ip = a['host']
        schema = "anomaly"
        engine = create_engine('mysql+mysqlconnector://{0}:{1}@{2}/{3}'.format(user, password, ip, schema))
        query = f"SELECT * FROM anomaly.{table_name}"
        with engine.connect() as conn:
            df = pd.read_sql(query, conn)
        return df
    def removeDataFromDatabase_temorary(table_name):
        a = readEncryptedConfig(r'/home/ubuntu/anomaly_data_pipeline/Data_Engg_Data_Science_Pre_Prod/Anomaly/Config/Paths.xls', env_local)
        user = a['user']
        pwd = a['password']
        password = urllib.parse.quote_plus(pwd)
        ip = a['host']
        schema = "anomaly"
        engine = create_engine('mysql+mysqlconnector://{0}:{1}@{2}/{3}'.format(user, password, ip, schema))
        query = text(f"TRUNCATE TABLE anomaly.{table_name}")
        with engine.connect() as conn:
            conn.execute(query)
        print("Done")
    gc.collect()
    def cleaned_matching_index(val):

        cleaned = re.sub(r'np\.int64\((\d+)\)', r'\1', str(val))
        return cleaned
    rulebased8.rename(columns={'Group_ID': 'Rulebased8_Group_ID'}, inplace=True)
    rulebased8 = rulebased8[rulebased8['Rulebased8_Group_ID'].notna()]
    rulebased10.rename(columns={'Group_ID': 'Rulebased10_Group_ID'}, inplace=True)
    rulebased10 = rulebased10[rulebased10['Rulebased10_Group_ID'].notna()]


    combined = pd.concat([rulebased8, rulebased10], ignore_index=True)
    rename_mapping = {
        'Chq_No': 'Check_Number',
        'Pay_Amount': 'Extended_Amount',
        'Inv_Date': 'Invoice_Date',
        'Inv_No': 'Invoice_Number',
        'Item_Desc': 'Line_Description',
        'Supp_No': 'Supplier',
        "Suppliers_Invoice_Number": 'Supplier_Invoice_Number',
        "Extended_Amount": "Pay_Amount2"

    }
    combined = combined.rename(columns=rename_mapping)


    global unique_values

    unique_values = {}
    global current_id
    current_id = 1
    def get_unique_id(value):
        global current_id
        if value not in unique_values:
            unique_values[value] = current_id
            current_id += 1
        return unique_values[value]
    potential_columns = ['Rulebased8_Group_ID', 'Rulebased10_Group_ID']
    columns = [col for col in potential_columns if col in combined.columns]

    combined['Matched_Record_Number'] = None
    combined['Priority_to_Validate'] = None

    for col in columns:
        for index, row in tqdm(combined.iterrows(), total=len(combined)):
            if pd.isna(combined.at[index, 'Matched_Record_Number']):
                value = row[col]
                if pd.notna(value):
                    unique_id = get_unique_id(f"{value}")
                    group_indices = combined[combined[col]==value].index
                    if all(pd.isna(combined.at[i, "Matched_Record_Number"]) for i in group_indices):
                        for i in group_indices:
                            combined.at[i, "Matched_Record_Number"]=unique_id
                            combined.at[i, "Priority_to_Validate"]=col



    print(f"Matched_Record_Number_unique - {combined['Matched_Record_Number'].nunique()}")
    print(f"step_3 - {combined.shape}")
    combined = combined.dropna(subset=['Matched_Record_Number'])
    combined = combined.drop(columns=columns)
    print(f"step_4 - {combined.shape}")
    def remove_all_negative_scanrios(group):
        if (group['Invoice_Amount'] < 0).any():
            group.loc[:, 'Matched_Record_Number'] = None
        return group
    print(f"step_5 - {combined.shape}")
    combined = combined.groupby('Matched_Record_Number', group_keys=False).progress_apply(remove_all_negative_scanrios)
    print(f"step_6 - {combined.shape}")
    #combined.to_csv(r'C:\Users\semen_k\Documents\Notebooks\step6.csv')
    combined = combined.dropna(subset=['Matched_Record_Number'])
    print(f"After_Matched_Record_Number: {combined.shape}")
    #combined.to_csv(r'C:\Users\semen_k\Documents\Notebooks\amrn.csv')

    del flag_check_number
    rename_mapping = {
        'Chq_No': 'Check_Number',
        'Pay_Amount': 'Extended_Amount',
        'Inv_Date': 'Invoice_Date',
        'Inv_No': 'Invoice_Number',
        'Item_Desc': 'Line_Description',
        'Supp_No': 'Supplier',
        "Suppliers_Invoice_Number": 'Supplier_Invoice_Number',
        "Extended_Amount" : "Pay_Amount2"

    }
    combined = combined.rename(columns=rename_mapping)
    combined['Extended Amount'] = combined['Pay_Amount2']
    combined['Iteration']= np.nan
    combined['Confirmed']="Y"
    combined['Recovery_Logics']=np.nan
    combined['Impact_Flag'] = combined.duplicated(subset=['Matched_Record_Number'], keep='first').astype(int).map({0:1, 1:0})
    combined['ConfirmedSpend'] = np.where((combined['Confirmed']=="Y") & (combined['Impact_Flag']==1), combined['Pay_Amount2'], 0)
    combined['confirmedSpendStatus'] = np.where((combined['Confirmed']=="Y") & (combined['Impact_Flag']==1) & (combined['Pay_Amount2']>0), "Confirmed amounts", "Duplicate to Confirmed amounts")
    combined['Invoice_Date'] = pd.to_datetime(combined['Invoice_Date'], format="mixed", errors = 'coerce')
    combined['MonthShort'] = combined['Invoice_Date'].dt.strftime('%b').str[0]
    combined['MonthNo']=combined['Invoice_Date'].dt.month
    combined['Year']=combined['Invoice_Date'].dt.year
    combined = combined.sort_values(by = 'Pay_Amount2')
    tot = combined['Pay_Amount2'].sum()
    combined['cums'] = combined['Pay_Amount2'].cumsum()
    combined['bucket_flag'] = combined.apply(lambda row: "Bucket_1" if row['cums'] <= tot*0.1
                                            else "Bucket_2" if row['cums'] <= tot*0.4
                                            else "Bucket_3", axis=1)
    combined.drop(columns=['cums'], inplace = True)
    combined['Created_On'] = pd.to_datetime(combined['Created_On'], format="mixed", errors = 'coerce')
    user_name = "semenk"
    combined['user_name'] = user_name
    combined['Supplier_Invoice_Number'] = combined['Suppliers_Invoice_Number_Semen_Old_For_Recovery']
    combined = combined.drop(['Suppliers_Invoice_Number_Semen_Old_For_Recovery'], axis=1)
    execution_id =1
    combined['execution_id'] = execution_id
    #combined['file_name'] = file_name
    combined['Reason_Grouped']= "ML1.3"
    combined['Impact_Flag'] = (combined['Pay_Amount2']==combined['Invoice_Amount']).astype(int)
    print(f"Before_final_step: {combined.shape}")
    def getDataFromDatabase():
        a = readEncryptedConfig(r'/home/ubuntu/anomaly_data_pipeline/Data_Engg_Data_Science_Pre_Prod/Anomaly/Config/Paths.xls', env_local)
        user = a['user']
        pwd = a['password']
        password = urllib.parse.quote_plus(pwd)
        ip = a['host']
        schema = "anomaly"
        engine = create_engine('mysql+mysqlconnector://{0}:{1}@{2}/{3}'.format(user, password, ip, schema))
        query = "SELECT * FROM anomaly.duplicate_ap_invoice"
        with engine.connect() as conn:
            df = pd.read_sql(query, conn)
        return df
    combined1 = getDataFromDatabase()
    if len(combined1)> 0:
        lastd = combined1['Matched_Record_Number'].max()
    else:
        lastd = 0
    if pd.isna(lastd):
        lastd = 0
    combined['Matched_Record_Number'] = combined['Matched_Record_Number'] + lastd
    columns_df1 = set(combined.columns)
    columns_df2 = set(combined1.columns)
    common_columns = columns_df1.intersection(columns_df2)
    print("Common")
    print(len(common_columns))
    print(common_columns)
    print("Unique in the processed data")
    unique_to_file1 = list(columns_df1 - columns_df2)
    print(len(unique_to_file1))
    print(unique_to_file1)
    print("Unique in output table in SQL")
    unique_to_file2 = list(columns_df2 - columns_df1)
    print(len(unique_to_file2))
    print(unique_to_file2)
    for a in unique_to_file2:
        combined[a] = None
    print(f"Before last step: {combined.shape}")
    combined = combined[combined1.columns]
    print(combined.shape)
    def uploadOutput(output):
        a = readEncryptedConfig(r'/home/ubuntu/anomaly_data_pipeline/Data_Engg_Data_Science_Pre_Prod/Anomaly/Config/Paths.xls', env_local)
        user = a['user']
        pwd = a['password']
        password = urllib.parse.quote_plus(pwd)
        ip = a['host']
        schema = "anomaly"
        engine = create_engine('mysql+mysqlconnector://{0}:{1}@{2}/{3}'.format(user, password, ip, schema))
        table_name ='duplicate_ap_invoice'
        output.to_sql(table_name, con = engine, if_exists='append', index=False)

    uploadOutput(combined)
    #combined.to_csv(r'C:\Users\semen_k\Documents\Notebooks\res.csv')


# In[7]:


def main():
    ML1()
    return


# In[8]:


if __name__ == "__main__":

    main()
    exit()


# In[ ]:

