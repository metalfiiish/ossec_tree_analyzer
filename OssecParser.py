#!/usr/bin/python
# Ossec Tree Analyzer
import csv
import re
import os
import graphviz as gv
import urllib2


#### Create a Web page that illustrates each parent rules tree structure of children
writeCheck=raw_input("Create Reports? ")
writeReports=False
if writeCheck != '' and writeCheck[0].lower() == 'y':
    writeReports=True


### Pre-Script booleans
reviewFailed=True

#########################
# Variables/Lists
#########################

DEBUG=False
reviewFailed=True # Will notify you of any rules it failed to parse
ossec_decoder='/usr/local/ossec/etc/decoder.xml' #File name for the decoder.xml (not yet implemented)
rules_dir='/usr/local/ossec/rules/' # Base rules directory
custom_rules='custom_rules.xml'
oem_rules='rules_config.xml'


rule_vars=[]
parent_rules={} #dictionary of all PARENT rule details (anything WITHOUT a "<if_*" tag)
child_rules ={} #dictionary of all CHILD rule details (anything WITH a "<if_*" tag)
failed_parsing={}


reporting_sets={

    'tag_object' : {
        "application" : {'desc' : "An application-level event", 'rules' : [] },
        "application av" : {'desc' : "An anti-virus event", 'rules' : [] },
        "application backdoor" : {'desc' : "An event using an application backdoor", 'rules' : [] },
        "application database" : {'desc' : "A database event", 'rules' : [] },
        "application database data" : {'desc' : "An event related to database data", 'rules' : [] },
        "application dosclient" : {'desc' : "An event involving a DOS client", 'rules' : [] },
        "application firewall" : {'desc' : "An event involving an application firewall", 'rules' : [] },
        "application im" : {'desc' : "An instant message-related event", 'rules' : [] },
        "application peertopeer" : {'desc' : "A peer to peer-related event", 'rules' : [] },
        "host" : {'desc' : "A host level event", 'rules' : [] },
        "group" : {'desc' : "A group level event", 'rules' : [] },
        "resource" : {'desc' : "An event involving system resources", 'rules' : [] },
        "resource cpu" : {'desc' : "An event involving the CPU", 'rules' : [] },
        "resource file" : {'desc' : "An event involving a file", 'rules' : [] },
        "resource interface" : {'desc' : "An event involving network interfaces", 'rules' : [] },
        "resource memory" : {'desc' : "An event involving memory", 'rules' : [] },
        "resource registry" : {'desc' : "An event involving the system registry", 'rules' : [] },
        "os" : {'desc' : "An OS-level event", 'rules' : [] },
        "os process" : {'desc' : "An event involving an OS-related process", 'rules' : [] },
        "os service" : {'desc' : "An event involving an OS service", 'rules' : [] },
        "user" : {'desc' : "A user-level event", 'rules' : [] },
        "log line" : {'desc' : "An event involving a log line", 'rules' : [] },
        "audit" : {'desc' : "An event involving an audit", 'rules' : [] },
        "application web server" : {'desc' : "An event involving a web server", 'rules' : [] },
        "application vpn" : {'desc' : "an event involving a vpn server", 'rules' : [] }
        },
    'tag_action' : {
        "access" : { 'desc' : "An event that accesses something", 'rules' : [] },
        "access read" : { 'desc' : "An event that reads something", 'rules' : [] },
        "access read copy" : { 'desc' : "An event that copies something", 'rules' : [] },
        "access read copy archive" : { 'desc' : "An event that archives something", 'rules' : [] },
        "access read decrypt" : { 'desc' : "An event that decrypts something", 'rules' : [] },
        "access read download" : { 'desc' : "An event that downloads something", 'rules' : [] },
        "access write" : { 'desc' : "An event that writes something", 'rules' : [] },
        "authentication" : { 'desc' : "An event involving authentication", 'rules' : [] },
        "authentication add" : { 'desc' : "An event adding authentication rules", 'rules' : [] },
        "authentication delete" : { 'desc' : "An event deleting authentication rules", 'rules' : [] },
        "authentication lock" : { 'desc' : "An event indicating an account lockout", 'rules' : [] },
        "authentication modify" : { 'desc' : "An event modifying authentication rules", 'rules' : [] },
        "authentication verify" : { 'desc' : "An event verifying identity", 'rules' : [] },
        "authorization" : { 'desc' : "An event involving authorization", 'rules' : [] },
        "authorization add" : { 'desc' : "Adding new priviliges", 'rules' : [] },
        "authorization delete" : { 'desc' : "Deleting privileges", 'rules' : [] },
        "authorization modify" : { 'desc' : "Changing privileges, e.g., chmod", 'rules' : [] },
        "authorization verify" : { 'desc' : "Checking privileges for an operation", 'rules' : [] },
        "attack" : { 'desc' : "An event involving an attack", 'rules' : [] },
        "attack ips" : { 'desc' : "An event involving an ips attack", 'rules' : [] },
        "attack ids" : { 'desc' : "An event involving an ids attack", 'rules' : [] },
        "check" : { 'desc' : "An event checking something", 'rules' : [] },
        "check status" : { 'desc' : "An event checking somethings status", 'rules' : [] },
        "create" : { 'desc' : "An event that creates something", 'rules' : [] },
        "communicate" : { 'desc' : "An event involving communication", 'rules' : [] },
        "communicate connect" : { 'desc' : "An event involving making a connection", 'rules' : [] },
        "communicate disconnect" : { 'desc' : "An event involving disconnecting", 'rules' : [] },
        "communicate firewall" : { 'desc' : "An event passing through a firewall", 'rules' : [] },
        "delete" : { 'desc' : "An event that deletes something", 'rules' : [] },
        "detect" : { 'desc' : "An event that detects something", 'rules' : [] },
        "detect virus" : { 'desc' : "An event that detects a virus", 'rules' : [] },
        "execute" : { 'desc' : "An event that runs something", 'rules' : [] },
        "execute restart" : { 'desc' : "An event that restarts something", 'rules' : [] },
        "execute start" : { 'desc' : "An event that starts something", 'rules' : [] },
        "execute stop" : { 'desc' : "An event that stops something", 'rules' : [] },
        "modify" : { 'desc' : "An event that changes something", 'rules' : [] },
        "modify attribute" : { 'desc' : "An event that changes an attribute", 'rules' : [] },
        "modify attribute rename" : { 'desc' : "An event that renames something", 'rules' : [] },
        "modify configuration" : { 'desc' : "An event that changes a configuration", 'rules' : [] },
        "modify content" : { 'desc' : "A content-related event", 'rules' : [] },
        "modify content append" : { 'desc' : "An event that appends new content onto existing content", 'rules' : [] },
        "modify content clear" : { 'desc' : "An event that clears out content", 'rules' : [] },
        "modify content insert" : { 'desc' : "An event that inserts content into existing content", 'rules' : [] },
        "modify content merge" : { 'desc' : "An event that merges content", 'rules' : [] },
        "monitor" : { 'desc' : "An event that monitored something", 'rules' : [] },
        "monitor ping" : { 'desc' : "An event that monitored something using ping", 'rules' : [] },
        "monitor memory" : { 'desc' : "An event that monitoring the memory of something", 'rules' : [] },
        "recon" : { 'desc' : "An event involving reconnaissance", 'rules' : [] },
        "recon portscan" : { 'desc' : "An event involving a port scan", 'rules' : [] },
        "substitute" : { 'desc' : "An event that replaces something", 'rules' : [] },
        "decode" : { 'desc' : "An event involving decoding something", 'rules' : [] },
        "classify" : { 'desc' : "An event involving classifying something", 'rules' : [] },
        "review" : { 'desc' : "An event that reviews something", 'rules' : [] },
        "qa event" : { 'desc' : "for testing only", 'rules' : [] },
        "monitor filesystem" : { 'desc' : "An event that monitored the filesystem of something", 'rules' : [] },
        "attack waf" : { 'desc' : "An event involving an web application attack", 'rules' : [] },
        "attack idps" : { 'desc' : "An event involving an ids or ips attack", 'rules' : [] },
        "detect wap" : { 'desc' : "An event that detects a wireless access point", 'rules' : [] },
        "execute scan" : { 'desc' : "An event that scans something", 'rules' : [] },
        "execute update" : { 'desc' : "An event that updates something", 'rules' : [] }
        },
    'tag_status' : {
        "attempt" : { 'desc' : "An event marking an attempt at something", 'rules' : [] },
        "deferred" : { 'desc' : "A deferred event", 'rules' : [] },
        "failure" : { 'desc' : "A failed event", 'rules' : [] },
        "inprogress" : { 'desc' : "An event marking something in-progress", 'rules' : [] },
        "report" : { 'desc' : "A report of a status", 'rules' : [] },
        "success" : { 'desc' : "A successful event", 'rules' : [] },
        "cleaned" : { 'desc' : "A cleaned event", 'rules' : [] },
        "blocked" : { 'desc' : "A blocked event", 'rules' : [] }
        }
    }

childless_parents=[]
tree_parents=[]

action_colors={ #used to identify actions by color
    'ignore':'#0BF2BC', #light blue
    'log':'#ECFF33', # yellow
    'review':'#5DFD57', # green
    'alert':'#EC6D47', # orange/red
    'log_line':'#C86BFD' # purple
    }
site_categories={'Web Services':['PHP Fatal error.',
                                                  'PHP Warning message.',
                                                  'PHP Parse error.',
                                                  'apache error log message group',
                                                  'Apache messages grouped.',
                                                  'Access log messages grouped.'],
                                 'LINUX':['Access log messages grouped.',
                                                  'Apache messages grouped.',
                                                  'SSHD messages grouped.',
                                                  'Nginx messages grouped.',
                                                  'Mountd Generic Log Message',
                                                  'syslog message group',
                                                  'Dpkg (Debian Package) log.',
                                                  'Red Hat messages grouped.',
                                                  'Squid messages grouped.',
                                                  'dansguardian message group'],
                                 'Cisco':['Grouping of Cisco VPN concentrator rules',
                                                  'cisco-nxos message group',
                                                  'Grouping of PIX rules',
                                                  'Grouping of Cisco 2811 rules.',
                                                  'Grouping of Cisco IOS rules.',
                                                  'cisco switch message group'],
                                 'Microsoft':['Grouping for the Microsoft ftp rules.',
                                                  'Grouping for the MS-DHCP rules.',
                                                  'Group of windows rules.'],#Windows png is the only buggy one so far :/
                                 'Penny Level Devices':['PaloAlto Firewall Event',
                                                                                'fortinet message group',
                                                                                'SonicWall messages grouped.',
                                                                                'Grouping for the Netscreen Firewall rules'],
                                 'OSSEC Agent Alerts':['ss-internal message group']}
#site_categories={}

#########################

#########################
# Functions
#########################


def br(j=None):
    raw_input(j)

def parseRules(rule_file_name):
    rule_filters=[]
    with open(rule_file_name, 'r') as raw_data:
        capturingRule=False
        rule_contents=[]

        print "Parsing rules"
        for line in raw_data:
            line=line.strip()
            #print "Demo Line: %s" %line
            # add var to variables db
            if re.match('^<var name=',line):
                continue #ignore for now
            elif re.match('^<group name=',line):
                continue #ignore for now
            elif re.match('.*rule id="\d+.*"',line):
                child=False
                failedParse=False
                capturingRule=True


            if capturingRule:

                #possible matches ['if_sid','if_group','if_level','if_matched_sid',if_matched_group']
                if re.match('.*<if_sid.*?>.*?</if_.*?>.*',line) or re.match('.*<if_matched_sid.*?>.*?</if_.*?>.*',line) or re.match('.*<if_matched_group.*?>.*?</if_.*?>.*',line) or re.match('.*<if_group.*?>.*?</if_.*?>.*',line):
                    child=True
                    rule_contents.append(line)
                elif re.match('.*<if_.*?>.*?</if_.*?>.*',line):
                    failedParse=True
                    child=True
                    rule_contents.append(line)

                elif re.match('.*</rule>.*',line):
                    #br("Ending capture. Building rule:\n\t%s\n" %rule_contents)
                    new_rule=decode_rule(rule_contents,action_colors)
                    if failedParse:
                        new_rule.isChild=child
                        failed_parsing[new_rule.id] = new_rule
                    elif child:
                        new_rule.isChild=child
                        child_rules[new_rule.id] = new_rule

                    else:
                        if new_rule.id not in rule_filters:
                             parent_rules[new_rule.id] =new_rule
                        #print "Parent ID: %s" %new_rule.id
                        #if writeReports:
                            #overview_graph.node(new_rule.id, new_rule.node,_attributes={'fontsize':'10'})


                    capturingRule=False
                    rule_contents=[]

                else:
                     rule_contents.append(line)

        return parent_rules,child_rules


def scanRules(master,new_maps,child_rules,gen,printOnly=False):
    next_rules=[]
    audit_list=[]
    childrenFound=False
    for c_map in new_maps:
        for n_r_id in c_map:
            new_children=c_map.get(n_r_id)

            for new_child in new_children:
                if printOnly:
                    print "\t~ %s:%s" %(new_child.id,new_child.desc)

                # Generation 1 style for dot graph
                elif gen == 1:
                    master.graph.node(new_child.id,label=new_child.node,_attributes={'shape':'octagon','fontsize':'10','fillcolor':new_child.node_color,'style':'filled'})

                # Sub Generation style for dot graph
                else:
                    master.graph.node(new_child.id,label=new_child.node,_attributes={'fontsize':'10','fillcolor':new_child.node_color,'style':'filled'})

                if not printOnly:
                    master.graph.edge(n_r_id,new_child.id)

                # Create next children list
                if new_child.getChildren(child_rules):
                    childrenFound=True
                    if new_child.id not in audit_list:
                        next_rules.append({new_child.id : new_child.children})
                        audit_list.append(new_child.id)


    return childrenFound,next_rules



def makeGhettoSite(href_data):
    header='''
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"

        "http://www.w3.org/TR/html4/loose.dtd">



<html lang="en">



<head>



        <meta http-equiv="content-type" content="text/html; charset=utf-8">

        <title>OSSEC Alert Manager Overview</title>
</head>



<body>

<p>OSSEC Alert Manager Overview (OAMO) is a brief overview of how OSSEC rules will trigger.</p>
                <TABLE cellspacing="0" border="0" cellborder="1" ALIGN="LEFT" VALIGN="TOP">
         <TR><TD bgcolor="grey"> <b><FONT POINT-SIZE="6">Action Legend </FONT></b></TD></TR>
         <TR><TD bgcolor="#0BF2BC"><FONT POINT-SIZE="3">IGNORE</FONT></TD></TR>
         <TR><TD bgcolor="#ECFF33"><FONT POINT-SIZE="3">LOG</FONT></TD></TR>
         <TR><TD bgcolor="#5DFD57"><FONT POINT-SIZE="3">REVIEW</FONT></TD></TR>
         <TR><TD bgcolor="#EC6D47"><FONT POINT-SIZE="3">ALERT</FONT></TD></TR>
        </TABLE><BR>

'''


    footer='''



</body>



</html>
'''
    #generate classifications
    with open('/usr/local/ossec/rules/OAMO_Categories','rb') as csvfile:
        imported_categories=csv.reader(csvfile)
        for new_category in imported_categories:
            current_category=new_category[0]
            current_rule=new_category[1]
            if current_rule in href_data:
                if current_category not in site_categories.keys():
                    site_categories[current_category] = [urllib2.unquote(current_rule)]
                else:
                    site_categories[current_category].append((urllib2.unquote(current_rule)))


    print "Categories Dynamiclly Added~: \n"
    categories = categorize_html(site_categories)

    # Build main page
    with open('/var/www/html/OAMO/OAMO.html','w') as ghetto_site:

        misc_rules='' #empty container for all rules that have yet to be categorized
        for href_link in href_data:
            # Add checks to exclude templates
            if not categories.categoryExists(href_link):
                    misc_rules += ('<a href="trees/%s.png">%s</a><br>\n' %(href_link,href_link))

        ghetto_site.write(header)
        ghetto_site.write(categories.web_code)
        ghetto_site.write(misc_rules)
        ghetto_site.write(footer)



#########################

#########################
# classes
#########################

class parent_decoder:
    def __init__(self):
        print "dummy"

class child_decoder:
    def __init__(self):
        print "dummy"

class decode_rule:

    def __init__(self,raw_details,colors):
        self.raw=raw_details
        self.color_options=colors
        self.parents=[]#holder for parent id's
        self.parent_groups=[]
        self.childids=[]
        self.desc=''
        self.node=''
        self.action=''
        self.graph=''
        self.graphs=[]
        self.isChild=False
        self.children=[]
        self.category=''
        self.groups=[]
        for line in self.raw:
            if re.match('.*<rule id\s*=\s*"\d+".*',line):
                name_res=re.search('.*?rule\s+id="(\d+)".*level\s*="(.*?)".*',line)
                self.id=name_res.group(1).strip() #id
                self.level=name_res.group(2).strip()#leve
                if re.match('.*<frequency\s*=\s*"\d+".*',line):
                    self.freq=re.search('.*?frequency\s*=\s*"(\d+)".*',line).group(1)
                    self.timeframe=re.search('.*?timeframe\s*=\s*"(\d+)".*',line).group(1)


            elif re.match('.*<category>.*',line):
                self.category=re.search('.*>(.*?)<.*',line).group(1).strip()

            elif re.match('.*<if_sid>.*', line) or re.match('.*<if_matched_sid>.*', line):
                self.isChild=True
                self.p_cap=re.sub('<.*?>','',line).split(',')
                for i in self.p_cap:
                    self.parents.append(i.strip())

            elif re.match('.*<if_matched_group>.*', line) or re.match('.*<if_group>.*', line):
                self.isChild=True
                self.g_cap=re.sub('<.*?>','',line).split(',')
                for r_grp in self.g_cap:
                    self.parent_groups.append(r_grp.strip())

            elif re.match('.*?<group>.*',line):
                new_groups=re.sub('<.*?>','',line).split(',')
                for new_group in new_groups:
                    if new_group:
                        self.groups.append(new_group)

            elif re.match('.*?<description>.*',line):
                self.desc+=re.sub('<.*?>','',line).strip()

            elif re.match('.*?<lrec_action>.*',line):
                self.action=re.sub('<.+?>','',line).strip()



        #print "DEBUG: Child Build %s" %self.raw
        self.node= "%s (%s)" %(self.desc,self.id)
        self.setNodeColor()


    def addChild(self,new_child):
        if new_child.id not in self.childids:
            self.children.append(new_child)
            self.childids.append(new_child.id)

    def getChildren(self,child_list):
        childFound=False
        for sch_id in child_list:
            sub_child=child_list.get(sch_id)
            if self.id in sub_child.parents:
                self.addChild(sub_child)
                childFound=True
            #add clauses to pick up other matches for if_
        return childFound

    def setGraph(self,new_graph):
        if self.isChild:
            self.graphs.append(new_graph)
        else:
            self.graph=new_graph

    def setNodeColor(self):
        self.node_color=self.color_options.get(self.action)

class categorize_html:

        def __init__(self, categories):
                self.site_categories = categories
                self.web_code=''
                self.add_tables()


        def categoryExists(self, url_name):
                for category in self.site_categories:
                        if url_name in self.site_categories.get(category):
                                return True
                return False

        def add_tables(self):

                end_template=u'''

        </table>
        <br><br>

        '''
                for table in self.site_categories:
                        links = self.site_categories.get(table)
                        start_template = u'''
                <table border="1" style="background-color:#FFFFCC;border-collapse:collapse;border:1px solid #FFCC00;color:#000000;width:100%%" cellpadding="3" cellspacing="3">
                        <tr>
                                <td><b>%s</b></td>
                        </tr>
                ''' %(str(table))
                        self.web_code += start_template
                        for link in links:
                                print "\tNew link added.. %s" %link
                                entry_template=u'''
                <tr>
                        <td><a href="trees/%s.png">%s</a><br></td>
                </tr>
        ''' %(link, link)
                                #if link == 'Group of windows rules.':
                                        #entry_template=entry_template.replace('.png"','.pdf"')#Hack to use pdf instead of png for this one buggy parent rule...TODO, fix it
                                self.web_code += entry_template
                        self.web_code += end_template


#########################

# Start
###

# create graph
#if writeReports:
    #overview_graph = gv.Digraph(format='png') #build graph
    #overview_graph.graph_attr={'rankdir':'LR'}
#create dictionary to hold graphs

itr_spacing="\t"

while not os.path.isfile(custom_rules):
    custom_rules = raw_input("Custom rules file does not exist, please specify where the rules are: ")

parent_rules,child_rules=parseRules("%s%s" %(rules_dir,custom_rules))
print "\t~Loaded rules"

if reviewFailed:
    for failed_rule in failed_parsing:
        failed=failed_parsing.get(failed_rule)
        #br( "Rule: %s %s" %(failed.node,failed.raw))

filters=''
if not writeReports:
    filters=raw_input('Quick Search Rule ID\'s: ')
if filters != '':
    filters=filters.split(',')
    print "\n\n\t $ Started with these filters: %s\n\n" %filters
    for f_id in filters:
        runs=0
        c_filter_rule='g'
        print "###############################################################\n Starting work on rule %s..." %(f_id)
        if f_id in parent_rules:
            print "\t\t~PARENT"
            c_filter_rule = parent_rules.get(f_id)
        elif f_id in child_rules:
            print "\t\t~CHILD"
            c_filter_rule = child_rules.get(f_id)
        else:
            print "\t~ Rule ID #%s: Not a child or parent rule." %(f_id)

        if not c_filter_rule == 'g' and c_filter_rule.getChildren(child_rules): #returns true if it has children
            runs+=1
            print "\t~!!! Has children..."
            print "\n\nMapping %s generation.." %runs
            keepGoing,new_mappings=scanRules(c_filter_rule,[{c_filter_rule.id: c_filter_rule.children}],child_rules,runs,True)
            while keepGoing:
                runs+=1
                print "\nMapping %s generation.." %runs
                keepGoing,new_mappings=scanRules(c_filter_rule,new_mappings,child_rules,runs,True)
        print "\n###############################################################\n"



elif writeReports:
    # MAP parents rules and their children

    for p_id in parent_rules:
        runs=0
        parent = parent_rules.get(p_id)

        #if DEBUG:
        print "\nParent: %s\n" %(parent.node)

        if parent.getChildren(child_rules): #returns true if it has children
            runs+=1
            tree_parents.append(parent.desc)
            #if parent has children, begin mapping a graph of it's tree
            if writeReports:
                parent.setGraph(gv.Digraph(format='png')) #set graph for this parent
                parent.graph.graph_attr={'rank':'max'}
                parent.graph.node('LEGEND',label='''<
      <TABLE cellspacing="0" border="0" cellborder="1" ALIGN="LEFT" VALIGN="TOP">
         <TR><TD bgcolor="grey"> <b><FONT POINT-SIZE="12">Action Legend </FONT></b></TD></TR>
         <TR><TD bgcolor="#0BF2BC"><FONT POINT-SIZE="9">IGNORE</FONT></TD></TR>
         <TR><TD bgcolor="#ECFF33"><FONT POINT-SIZE="9">LOG</FONT></TD></TR>
         <TR><TD bgcolor="#5DFD57"><FONT POINT-SIZE="9">REVIEW</FONT></TD></TR>
         <TR><TD bgcolor="#EC6D47"><FONT POINT-SIZE="9">ALERT</FONT></TD></TR>
        </TABLE>
   >''',_attributes={'shape':'none','margin':'0'})
                parent.graph.graph_attr={'rankdir':'LR'}
                parent.graph.node(parent.id,label=parent.node,_attributes={'shape':'doubleoctagon','fontsize':'12','fillcolor':parent.node_color,'style':'filled'})


            if DEBUG:
                print "%sChildren:" %itr_spacing

            ## new patch for child iteration
            print "\t~Mapping %s generation.." %runs
            keepGoing,new_mappings=scanRules(parent,[{parent.id: parent.children}],child_rules,runs)
            while keepGoing:
                runs+=1
                print "\t~Mapping %s generation.." %runs
                keepGoing,new_mappings=scanRules(parent,new_mappings,child_rules,runs)
            ## end patch

            if writeReports:
                parent.graph.render('/var/www/html/OAMO/trees/%s' %parent.desc)


        else: #This parent rule has No children, add it to records as to minimize space on graph since it has no further tree

            print "\t!!! No children for this parent. Skiped child tree mapping. !!!"
            childless_parents.append(parent.node)

else:
    print "\tReporting Disabled; but no filters set....moving to manual mode..."
    cmd=''
    while cmd != 'stop':
        cmd=raw_input('Search: ').strip()
        if cmd == 'rule':
            c_rule='g'
            c_id=raw_input("Rule ID: ")
            if c_id == 'stop':
                cmd='stop'
            elif c_id in parent_rules:
                c_rule=parent_rules.get(c_id)
            elif c_id in child_rules:
                c_rule=child_rules.get(c_id)
            if c_rule != 'g':
                print "\n\tRule ID: %s\n\tDescription: %s\n\tAction: %s\n" %(c_rule.id,c_rule.desc,c_rule.action)
                for ir in c_rule.raw:
                    print "\t\t%s" %ir.strip()
                print "\n\tChildren:"
                if c_rule.getChildren(child_rules):
                    for c_child in c_rule.children:
                        print "\t\t\t%s: %s  >>> (%s)" %(c_child.id,c_child.desc,c_child.action)

            elif cmd !='stop':
                print "\tNo rule found!"


        elif cmd  == 'lookup':
            term=raw_input('Key: ').lower().strip()
            if term == 'stop':
                cmd=term
            else:
                print "\t...searching Parent rules..."
                for p in parent_rules:
                    if term in parent_rules.get(p).desc.lower():
                        fpt=parent_rules.get(p)
                        print "\t\t%s: %s" %(fpt.id,fpt.desc)

                print "\n\t...searching Child rules..."
                for p in child_rules:
                    if term in child_rules.get(p).desc.lower():
                        fpt=child_rules.get(p)
                        print "\t\t%s: %s" %(fpt.id,fpt.desc)

        elif cmd  == 'failed':
            print "loading failed rules...\n"
            if reviewFailed:
                for failed_rule in failed_parsing:
                    failed=failed_parsing.get(failed_rule)
                    print failed.desc
                    for entry in failed.raw:
                        print "\t%s" %entry.strip()
                    br(' ')

        elif cmd  == 'group':
            grp_chk=raw_input("Group Name: ")
            print "Finding rules associated with that group"
            print "\t~PARENT RULES - assigning group:"
            for ps in parent_rules:
                p=parent_rules.get(ps)
                if not grp_chk:
                    if p.groups:
                        print "\t\t%s" %p.groups
                elif grp_chk in p.groups:
                    print "\t\t%s" %p.node

            print "\t~CHILD RULES - assigning group:"
            for cs in child_rules:
                c=child_rules.get(cs)
                if not grp_chk:
                    if c.groups:
                        print "\t\t%s" %c.groups
                elif grp_chk in c.groups:
                    print '\t\t%s' %c.node

            print "\n\t~SUB-PARENT RULES - if group triggered:"
            for sps in parent_rules:
                sp=parent_rules.get(sps)
                if not grp_chk:
                    if sp.parent_groups:
                        print "\t\t%s" %sp.parent_groups
                elif grp_chk in sp.parent_groups:
                    print '\t\t%s' %sp.node

            print "\t~SUB-CHILD RULES - if group triggered:"
            for scs in child_rules:
                sc=child_rules.get(scs)
                if not grp_chk:
                    if sc.parent_groups:
                        print "\t\t%s" %sc.parent_groups
                elif grp_chk in sc.parent_groups:
                    print '\t\t%s' %sc.node


        elif cmd  == 'action':
            act=raw_input("Rule ID's:(I forget why and where I was gonig with this...) ").split(',')


        elif cmd  == 'audit':

            print "\n\nStarting audit of alerts...."
            os.system('/root/os2')
            with open('raw_dump','r') as audit_contents:
                for audit_line in audit_contents:
                    if 'Rule' in audit_line:
                        audit_rule_id=re.search('.+\sRule:\s(\d+)\s.+',audit_line).group(1)
                        if audit_rule_id in parent_rules:
                            audit_rule=parent_rules.get(audit_rule_id)
                        elif audit_rule_id in child_rules:
                            audit_rule=child_rules.get(audit_rule_id)
                        print "Action: %s  >>>  %s" %(audit_rule.action,audit_line.strip())

        elif cmd == '':
            print "\t~Help Menu~\n\taudit - run custom parse against raw_dump\n\taction - N/A (incomplete)\n\trule - find rule details by id\n\tlookup - locate rules by string name\n\tfailed - print rules that failed parsing\n\tgroup - find all rules for a given group\n\n"



#overview_graph.render('OAMO/overview')
makeGhettoSite(tree_parents)
