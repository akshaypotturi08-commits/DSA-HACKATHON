package securitygate;

import java.util.*;
import java.io.*;

/* USER CLASS */
class User {

    String name;
    String cardId;
    String role;

    User(String name,String cardId,String role){
        this.name=name;
        this.cardId=cardId;
        this.role=role;
    }
}

/* ZONE ACCESS NODE */
class ZoneAccess{

    String zone;
    int count;

    ZoneAccess(String zone){
        this.zone=zone;
        this.count=1;
    }
}

/* ACCESS LOG LINKED LIST */
class LogNode{

    String user;
    String zone;
    String time;
    LogNode next;

    LogNode(String u,String z,String t){
        user=u;
        zone=z;
        time=t;
    }
}

class AccessLog{

    LogNode head;

    void addLog(String user,String zone,String time){

        LogNode newNode=new LogNode(user,zone,time);
        newNode.next=head;
        head=newNode;

        try{
            FileWriter fw=new FileWriter("logs.txt",true);
            fw.write(user+","+zone+","+time+"\n");
            fw.close();
        }catch(Exception e){
            System.out.println("Log file error");
        }
    }

    void displayLogs(){

        LogNode temp=head;

        if(temp==null){
            System.out.println("No logs");
            return;
        }

        while(temp!=null){
            System.out.println(temp.user+" -> "+temp.zone+" -> "+temp.time);
            temp=temp.next;
        }
    }
}

/* VISITOR QUEUE */
class VisitorQueue{

    Queue<String> visitors=new LinkedList<>();

    void addVisitor(String name){

        visitors.add(name);

        try{
            FileWriter fw=new FileWriter("visitors.txt",true);
            fw.write(name+"\n");
            fw.close();
        }catch(Exception e){
            System.out.println("Visitor file error");
        }

        System.out.println("Visitor added");
    }

    void processVisitor(){

        if(visitors.isEmpty())
            System.out.println("No visitors");
        else
            System.out.println("Processing visitor: "+visitors.poll());
    }
}

/* ALERT PRIORITY QUEUE */
class Alert implements Comparable<Alert>{

    int severity;
    String message;

    Alert(int s,String m){
        severity=s;
        message=m;
    }

    public int compareTo(Alert a){
        return this.severity-a.severity;
    }
}

class AlertManager{

    PriorityQueue<Alert> alerts=new PriorityQueue<>();

    void addAlert(int s,String msg){

        alerts.add(new Alert(s,msg));

        try{
            FileWriter fw=new FileWriter("alerts.txt",true);
            fw.write(s+","+msg+"\n");
            fw.close();
        }catch(Exception e){
            System.out.println("Alert file error");
        }

        System.out.println("Alert added");
    }

    void handleAlert(){

        if(alerts.isEmpty()){
            System.out.println("No alerts");
            return;
        }

        Alert a=alerts.poll();
        System.out.println("Handling alert: "+a.message+" Severity:"+a.severity);
    }
}

/* RULE STACK */
class RuleManager{

    Stack<String> rules=new Stack<>();

    void addRule(String r){
        rules.push(r);
        System.out.println("Rule added");
    }

    void undoRule(){

        if(rules.isEmpty())
            System.out.println("No rule");
        else
            System.out.println("Undo rule: "+rules.pop());
    }
}

/* GUARD CLASS */
class Guard{

    String name;
    String location;

    Guard(String name,String location){
        this.name=name;
        this.location=location;
    }
}

/* GUARD CIRCULAR QUEUE */
class GuardShift{

    Guard guards[];
    int front=0,rear=0,count=0,size;

    GuardShift(int size){
        this.size=size;
        guards=new Guard[size];
    }

    void addGuard(String name,String location){

        if(count==size){
            System.out.println("Queue full");
            return;
        }

        guards[rear]=new Guard(name,location);
        rear=(rear+1)%size;
        count++;

        System.out.println("Guard added");
    }

    void nextShift(){

        if(count==0){
            System.out.println("No guards");
            return;
        }

        Guard g=guards[front];

        System.out.println("Current guard: "+g.name);
        System.out.println("Location: "+g.location);

        front=(front+1)%size;
    }

    void showCurrentGuard(){

        if(count==0){
            System.out.println("No guard");
            return;
        }

        Guard g=guards[front];

        System.out.println("Guard on duty: "+g.name);
        System.out.println("Location: "+g.location);
    }

    void searchGuard(String name){

        boolean found=false;

        for(int i=0;i<count;i++){

            Guard g=guards[(front+i)%size];

            if(g.name.equalsIgnoreCase(name)){
                System.out.println("Guard: "+g.name);
                System.out.println("Location: "+g.location);
                found=true;
            }
        }

        if(!found)
            System.out.println("Guard not found");
    }

    void showAllGuards(){

        if(count==0){
            System.out.println("No guards");
            return;
        }

        for(int i=0;i<count;i++){

            Guard g=guards[(front+i)%size];

            System.out.println(g.name+" -> "+g.location);
        }
    }
}

/* MAIN CLASS */
public class Securegate{ 

    static Scanner sc=new Scanner(System.in);

    static LinkedList<User> users=new LinkedList<>();
    static LinkedList<ZoneAccess> zoneAccess=new LinkedList<>();

    static AccessLog logs=new AccessLog();
    static VisitorQueue visitors=new VisitorQueue();
    static AlertManager alerts=new AlertManager();
    static RuleManager rules=new RuleManager();
    static GuardShift guards=new GuardShift(5);

    static String zones[]={"Gate","Lab","ServerRoom","Office"};

    static void showZones(){

        System.out.println("Zones:");
        for(String z:zones)
            System.out.println(z);
    }

    static User findUser(String card){

        for(User u:users){
            if(u.cardId.equals(card))
                return u;
        }

        return null;
    }

    static void updateZone(String zone){

        for(ZoneAccess z:zoneAccess){
            if(z.zone.equals(zone)){
                z.count++;
                return;
            }
        }

        zoneAccess.add(new ZoneAccess(zone));
    }

    static void showAccessPattern(){

        for(ZoneAccess z:zoneAccess)
            System.out.println(z.zone+" -> "+z.count);
    }

    public static void main(String args[]){

        while(true){

            System.out.println("\n--- SecureGate Menu ---");
            System.out.println("1 Add User");
            System.out.println("2 Verify Access");
            System.out.println("3 Show Logs");
            System.out.println("4 Add Visitor");
            System.out.println("5 Process Visitor");
            System.out.println("6 Add Alert");
            System.out.println("7 Handle Alert");
            System.out.println("8 Add Rule");
            System.out.println("9 Undo Rule");
            System.out.println("10 Add Guard");
            System.out.println("11 Next Guard");
            System.out.println("12 Show Guard Location");
            System.out.println("13 Search Guard");
            System.out.println("14 Show All Guards");
            System.out.println("15 Show Access Pattern");
            System.out.println("16 Exit");

            int ch=Integer.parseInt(sc.nextLine());

            switch(ch){

                case 1:

                    System.out.print("Name: ");
                    String name=sc.nextLine();

                    System.out.print("Card ID: ");
                    String card=sc.nextLine();

                    System.out.print("Role: ");
                    String role=sc.nextLine();

                    users.add(new User(name,card,role));
                    System.out.println("User added");
                    break;

                case 2:

                    System.out.print("Card ID: ");
                    String cid=sc.nextLine();

                    User u=findUser(cid);

                    if(u==null){
                        System.out.println("Access denied");
                    }else{

                        showZones();

                        System.out.print("Zone: ");
                        String zone=sc.nextLine();

                        updateZone(zone);

                        String time=new Date().toString();

                        logs.addLog(u.name,zone,time);

                        System.out.println("Access granted");
                    }

                    break;

                case 3:
                    logs.displayLogs();
                    break;

                case 4:

                    System.out.print("Visitor name: ");
                    visitors.addVisitor(sc.nextLine());
                    break;

                case 5:
                    visitors.processVisitor();
                    break;

                case 6:

                    try{
                        System.out.print("Severity (number): ");
                        int s=Integer.parseInt(sc.nextLine());

                        System.out.print("Message: ");
                        String msg=sc.nextLine();

                        alerts.addAlert(s,msg);
                    }
                    catch(Exception e){
                        System.out.println("Invalid severity input");
                    }

                    break;

                case 7:
                    alerts.handleAlert();
                    break;

                case 8:

                    System.out.print("Rule: ");
                    rules.addRule(sc.nextLine());
                    break;

                case 9:
                    rules.undoRule();
                    break;

                case 10:

                    System.out.print("Guard name: ");
                    String gname=sc.nextLine();

                    System.out.print("Guard location: ");
                    String gloc=sc.nextLine();

                    guards.addGuard(gname,gloc);
                    break;

                case 11:
                    guards.nextShift();
                    break;

                case 12:
                    guards.showCurrentGuard();
                    break;

                case 13:

                    System.out.print("Guard name: ");
                    guards.searchGuard(sc.nextLine());
                    break;

                case 14:
                    guards.showAllGuards();
                    break;

                case 15:
                    showAccessPattern();
                    break;

                case 16:
                    System.exit(0);
            }
        }
    }
}