from os import walk
from os import path
import os
import yaml
import subprocess
import threading
import shutil

# get total number of vulnerabilities (count files in ./data dir)
def GetTotalVulns():
    return len([name for name in os.listdir("./data") if os.path.isfile(os.path.join("./data", name))])

user = 'toastr'
score = 0
total_score = 100
vulns_found = 0
total_vulns = GetTotalVulns()

REPLACEMENTS = {'Current Score':str(score), '[Total Score]':str(total_score), 'Number of Found':str(vulns_found), '[Total Number]': str(total_vulns)}

def main():
    # generate blank score report w/
    # number of vulns
    # total number of points
    GenerateScoreReport()
    
    CheckDataFiles_stop = threading.Event()
    CheckDataFiles(CheckDataFiles_stop)
    
    UpdateScoreReport_stop = threading.Event()
    UpdateScoreReport(UpdateScoreReport_stop)

# update score and vulns found in score report
def WriteUpdatesToScoreReport(oldScore, oldVulns):
    global score
    global vulns_found
    global total_score
    
    replacements = {'['+str(oldScore)+'] out of ' + str(total_score):'['+str(score)+'] out of ' + str(total_score), 'Found ['+str(oldVulns)+']':'Found ['+str(vulns_found)+']'}
    
    # read through lines of score report and update those that need to be
    lines = []
    with open("/home/"+user+"/Desktop/Score_Report.txt", "r") as file:
        for line in file:
            for src, target in replacements.items():
                line = line.replace(src, target)
            lines.append(line)
            
    # write updates to file
    with open("/home/"+user+"/Desktop/Score_Report.txt", "w") as file:
        for line in lines:
            file.write(line)

# generate initial score report if not already generated
def GenerateScoreReport():
    # check if score report exists
    if not path.exists("/home/"+user+"/Desktop/Score_Report.txt"):
        # copy template
        shutil.copyfile("./score_report_template.txt", "/home/"+user+"/Desktop/Score_Report.txt")
        
        # read and replace old data
        lines = []
        with open("/home/"+user+"/Desktop/Score_Report.txt", "r") as file:
            for line in file:
                for src, target in REPLACEMENTS.items():
                    line = line.replace(src, target)
                lines.append(line)
                
        # write new data
        with open("/home/"+user+"/Desktop/Score_Report.txt", "w") as file:
            for line in lines:
                file.write(line)
            
# update score report to match yaml data
def UpdateScoreReport(f_stop):
    global score
    global vulns_found
    
    # get all data files
    dataFiles = []
    for (dirpath, dirnames, filenames) in walk("./data"):
        dataFiles.extend(filenames)
        break
    
    # get lines from score report
    lines = []
    with open("/home/"+user+"/Desktop/Score_Report.txt", "r") as file:
        for line in file:
            lines.append(line)
    
    for dataFile in dataFiles:
        with open("./data/"+dataFile, "r") as stream:
            try:
                # load yaml data
                data = yaml.safe_load(stream)
                
                # if the vuln is found and not already found
                if data["IsFound"] == True and data["IsMarked"] == False:
                    with open("/home/"+user+"/Desktop/Score_Report.txt", "a") as file:
                        # write message to file
                        file.write(data["Message"]+"\n")
                        
                        # change IsMarked to True
                        data["IsMarked"] = True
                        with open("./data/"+dataFile, "w", encoding='utf8') as outfile:
                            yaml.dump(data, outfile, allow_unicode=True)
                            
                        # increment vulns found and points                        
                        oldScore = score
                        oldVulns = vulns_found
                        
                        score += data["PointValue"]
                        vulns_found += 1
                        
                        # update score report
                        WriteUpdatesToScoreReport(oldScore, oldVulns)
                        
                        # send notif
                        subprocess.run(["notify-send", "-u", "normal", "-t", "3000", "Scoring Engine", "You Gained Points!"], check=True)
                # remove the message, points, and vuln found if no longer found
                elif data["IsFound"] == False and data["IsMarked"] == True:
                    # delete message from file
                    file = open("/home/"+user+"/Desktop/Score_Report.txt", 'r')
                    lst = []
                    for line in file:
                        if data["Message"] in line:
                            line = line.replace(data["Message"], '').strip()
                        lst.append(line)
                    file.close()
                    
                    # write new data to file
                    file = open("/home/"+user+"/Desktop/Score_Report.txt", 'w')
                    for line in lst:
                        file.write(line)
                    file.close()
                    
                    # change IsMarked to false
                    data["IsMarked"] = False
                    with open("./data/"+dataFile, "w", encoding='utf8') as outfile:
                            yaml.dump(data, outfile, allow_unicode=True)
                    
                     # decrement vulns found and points                    
                    oldScore = score
                    oldVulns = vulns_found
                    
                    score -= data["PointValue"]
                    vulns_found -= 1
                    
                    # update score report
                    WriteUpdatesToScoreReport(oldScore, oldVulns)
                    
                    # send notif
                    subprocess.run(["notify-send", "-u", "normal", "-t", "3000", "Scoring Engine", "You Lost Points!"], check=True)

                        
            except yaml.YAMLError as exc:
                print(exc)
    if not f_stop.is_set():
        threading.Timer(30, UpdateScoreReport, [f_stop]).start()

# Checks the data files for command and expected return code, updates yaml file if they match
def CheckDataFiles(f_stop):
    # get all data files
    dataFiles = []
    for (dirpath, dirnames, filenames) in walk("./data"):
        dataFiles.extend(filenames)
        break
    
    for dataFile in dataFiles:
        with open("./data/"+dataFile, "r") as stream:
            try:
                # load yaml data
                data = yaml.safe_load(stream)
                
                # run command
                osstdout = subprocess.Popen(data["Command"], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
                
                # check exit status of commmand
                output = osstdout.communicate()[0].strip()
                if str(osstdout.returncode) == data["Check"]:                    
                    # update file to show IsFound to true
                    data["IsFound"] = True
                    with open("./data/"+dataFile, "w", encoding='utf8') as outfile:
                        yaml.dump(data, outfile, allow_unicode=True)
                    
                else:
                    # update file to show IsFound to false
                    data["IsFound"] = False
                    with open("./data/"+dataFile, "w", encoding='utf8') as outfile:
                        yaml.dump(data, outfile, allow_unicode=True)
                
            except yaml.YAMLError as exc:
                print(exc)
    
    if not f_stop.is_set():
        threading.Timer(30, CheckDataFiles, [f_stop]).start()

# run poose
if __name__ == "__main__":
    main()