package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import java.util.Map;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.widget.Switch;

public class SimpleDhtProvider extends ContentProvider {

    private String my_id;
    private String prev_id;
    private String succ_id;
    static final int SERVER_PORT = 10000;
    private String my_port;
    private String prev_port;
    private String succ_port;
    private String to_port;
    static final String CENTRAL_PORT = "11108";
    static final String TAG = SimpleDhtProvider.class.getSimpleName();
    private Uri myUri;
    private String Dump_message;
    boolean isComplete = false;
    private String global_message = null;
    private String local_message = null;
    private static final Map<String, String > Storage = null;

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {

        String Delete_file=null;


        if(selection.equals("@")||(selection.equals("*")&&(prev_id.equals(my_id)))) {

            for (String file_delete : getContext().fileList()) {
                  getContext().deleteFile(file_delete);
            }
        }
        else if(selection.equals("*")&&(!prev_id.equals(my_id))){
            for (String file_delete : getContext().fileList()) {
                getContext().deleteFile(file_delete);
            }
            String Delete_m = "DELETE"+","+"*"+","+my_port+","+""+","+""+",\n";
            ClientTask(Delete_m, succ_port,Storage);

        }
        else {

            try {
                Delete_file = genHash(selection);

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            if (prev_id.compareTo(my_id) < 0) {
                if (Delete_file.compareTo(prev_id) > 0 && Delete_file.compareTo(my_id) <= 0) {
                    getContext().deleteFile(selection);
                } else {
                    String Delete_m = "DELETE"+","+selection+","+my_port+","+""+","+""+",\n";
                    ClientTask(Delete_m, succ_port,Storage);

                }
            }
            else if (prev_id.compareTo(my_id) > 0) {

                if (Delete_file.compareTo(my_id) <= 0 || Delete_file.compareTo(prev_id) > 0) {
                    getContext().deleteFile(selection);

                }  else {
                    String Delete_m = "DELETE"+","+selection+","+my_port+","+""+","+""+",\n";
                    ClientTask(Delete_m, succ_port,Storage);

                }
            }
            else if (prev_id.compareTo(my_id) == 0) {
                getContext().deleteFile(selection);
            }


        }


            return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        FileOutputStream outputStream;
        String filename = values.get("key").toString();
        String string = values.get("value").toString();
        String hashed_key=null;
        Log.d(TAG, " During insert in my port " + my_port + " prevport is" + prev_port + " succport is  " + succ_port);
        Log.d(TAG,"Started Inserting in "+my_port+ " with "+filename+ " with value as "+string);
        try {
            hashed_key = genHash(filename);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

       try {
           if (prev_id.compareTo(my_id) < 0) {
               if (hashed_key.compareTo(prev_id) > 0 && hashed_key.compareTo(my_id) <= 0) {
                   outputStream = getContext().openFileOutput(filename, Context.MODE_PRIVATE);
                   outputStream.write(string.getBytes());
                   Log.d(TAG,"Inserted Sucessfully here in "+my_port+" with "+filename+ " with value as "+string);
                   outputStream.close();
               } else {
                   Log.d(TAG,"forward to "+succ_port+" with "+filename+ " with value as "+string);
                   to_port = succ_port;
                   String insert_message = "INSERT" + "," + filename + "," + "" + "," + "" + "," + string + ",\n";
                   ClientTask(insert_message, to_port,Storage);

               }
           } else if (prev_id.compareTo(my_id) > 0) {

               if (hashed_key.compareTo(my_id) <= 0 || hashed_key.compareTo(prev_id) > 0) {
                   Log.d(TAG,"Inserted Sucessfully here in "+my_port+" with "+filename+ " with value as "+string);
                   outputStream = getContext().openFileOutput(filename, Context.MODE_PRIVATE);
                   outputStream.write(string.getBytes());
                   outputStream.close();

               } else {
                   Log.d(TAG,"forward to "+succ_port+" with "+filename+ " with value as "+string);
                   to_port = succ_port;
                   String insert_message = "INSERT" + "," + filename + "," + "" + "," + "" + "," + string + ",\n";
                   ClientTask(insert_message, to_port,Storage);

               }
           } else if (prev_id.compareTo(my_id) == 0) {
               Log.d(TAG,"Inserted Sucessfully here in "+my_port+" with "+filename+ " with value as "+string);
               outputStream = getContext().openFileOutput(filename, Context.MODE_PRIVATE);
               outputStream.write(string.getBytes());
               outputStream.close();

           }
          // else {
           //    Log.d(TAG,"forward to "+succ_port+" with "+filename+ " with value as "+string);
            //   to_port = succ_port;
            //   String insert_message = "INSERT" + "," + filename + "," + "" + "," + "" + "," + string + ",\n";
            //   new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, insert_message, to_port);
          // }
       }  catch(NullPointerException e) {
           Log.e("Uri insert", "Null pointer exception");
       } catch (Exception e) {
           Log.e("Uri insert", "File write failed");
       }

        // TODO Auto-generated method stub
        return uri;
    }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub
        Uri.Builder uriBuilder = new Uri.Builder();
        uriBuilder.authority("edu.buffalo.cse.cse486586.simpledht.provider");
        uriBuilder.scheme("content");
        myUri = uriBuilder.build();

        TelephonyManager tel = (TelephonyManager)this.getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        final String myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        my_port = myPort;
        prev_port=myPort;
        succ_port=myPort;


        try {

            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);

            ServerTask(serverSocket);
        } catch (IOException e) {
            Log.e(TAG, "Can't create a ServerSocket");
            return false;
        }


       try {
            my_id = genHash(portStr);
            prev_id = my_id;
            succ_id = my_id;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        Log.d(TAG, "server socket started at "+myPort+" with prev as "+prev_port+" and successor "+succ_port);
        Log.d(TAG, "server socket started at "+my_id+" with prev as "+prev_id+" and successor "+succ_id);
         //string format = fwdport+key+value+type+prev_succ;
         to_port = CENTRAL_PORT;
        String new_join_message = "NEW_NODE"+","+my_port+","+prev_port+","+succ_port+","+""+",\n";

        if(!myPort.equals(CENTRAL_PORT)){
            ClientTask(new_join_message,to_port,Storage);
        }

        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder) {

        MatrixCursor newCursor = new MatrixCursor(new String[]{"key","value"});
        String Q_values = null;
        FileInputStream inputStream;
        Log.d(TAG, "started query mode");
        if(selection.equals("@")||(selection.equals("*")&&(prev_id.equals(my_id)))){
           try{
               for(String file_N : getContext().fileList()){
                   inputStream = getContext().openFileInput(file_N);
                   BufferedReader in = new BufferedReader(new InputStreamReader(inputStream));
                   Q_values = in.readLine();
                   newCursor.addRow(new Object[]{file_N,Q_values});

               }
           } catch (FileNotFoundException e) {
               e.printStackTrace();
           } catch (IOException e) {
               e.printStackTrace();
           }

           return  newCursor;

        }
        else if(selection.equals("*")&&(!prev_id.equals(my_id))){
            try{
                for(String file_N : getContext().fileList()){
                    inputStream = getContext().openFileInput(file_N);
                    BufferedReader in = new BufferedReader(new InputStreamReader(inputStream));
                    Q_values = in.readLine();
                    Dump_message += file_N+":"+Q_values+"&";
                    //newCursor.addRow(new Object[]{file_N,Q_values});

                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }

              String Dump_m = "DUMP"+","+my_port+","+""+","+""+","+Dump_message+",\n";
            ClientTask(Dump_m,succ_port,Storage);
            while(!isComplete){
                try{
                    Thread.sleep(30);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            isComplete = false;
            Log.d(TAG,"in the query part "+ global_message);

           String m1 = global_message.substring(4,global_message.length()-1);
            Log.d(TAG,"in the query part "+ m1);

            String[] m2 = m1.split("&");
            //Log.d(TAG,"in the query part "+ m2[0]);
            //Log.d(TAG,"in the query part "+ m2[5]);
            //Log.d(TAG,"in the query part "+ m2[10]);
            //Log.d(TAG,"in the query part "+ m2[24]);
            for(String pair : m2){
                String [] m3 = pair.split(":");
                newCursor.addRow(new Object[]{m3[0],m3[1]});
            }
            global_message = null;

           return newCursor;

        }

        else {
            Log.d(TAG, "entered normal key query");
            String new_key = null;
            try {
                new_key = genHash(selection);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            if (prev_id.compareTo(my_id) < 0) {
                if (new_key.compareTo(prev_id) > 0 && new_key.compareTo(my_id) <= 0) {
                    Q_values = query_one(selection);

                } else {
                    to_port = succ_port;
                    String Query_One_m = "QUERY"+","+selection+","+my_port+","+""+","+""+",\n";
                    ClientTask(Query_One_m, to_port,Storage);
                    while(!isComplete){
                        try{
                            Thread.sleep(30);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                    isComplete = false;
                    Q_values = local_message;
                    local_message = null;

                }
            } else if (prev_id.compareTo(my_id) > 0) {

                if (new_key.compareTo(my_id) <= 0 || new_key.compareTo(prev_id) > 0) {

                    Q_values = query_one(selection);
                } else {
                    to_port = succ_port;
                    String Query_One_m = "QUERY"+","+selection+","+my_port+","+""+","+""+",\n";
                    ClientTask(Query_One_m, to_port,Storage);
                    while(!isComplete){
                        try{
                            Thread.sleep(30);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                    isComplete = false;
                    Q_values = local_message;
                    local_message = null;
                }
            } else if (prev_id.compareTo(my_id) == 0) {
                Log.d(TAG, "entered single node query mode");
                Q_values = query_one(selection);
                Log.d(TAG, "got back value"+Q_values);
            }

            newCursor.addRow(new Object[]{selection,Q_values});
            return newCursor;

        }
        //return null;
    }

    public String query_one(String Selection){
        Log.d(TAG, "called query fucntion");
        String values2 = null;
        FileInputStream inputStream2;

        try{
            inputStream2 = getContext().openFileInput(Selection);
            BufferedReader in2 = new BufferedReader(new InputStreamReader(inputStream2));
            values2 = in2.readLine();
            in2.close();
        }
        catch(FileNotFoundException e){
            Log.e("Cursor query", "File not found Exception");

        }  catch(NullPointerException e) {
            Log.e("Cursor query", "Null pointer exception");
        }
        catch (IOException e) {
            Log.e("Cursor query", " IOException");
        }

        Log.d(TAG, "completed query chedck"+values2+"for"+Selection);

        return values2;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }





        private Void ServerTask(final ServerSocket sockets) {
            new Thread(new Runnable() {
                public void run() {
                    ServerSocket serverSocket = sockets;
                    String inputLine;
                    String new_id = null;
                    FileInputStream inputStream1;
                    String Q_values1;
                    String local_Query;

                    //the below code has been taken from https://docs.oracle.com/javase/tutorial/networking/sockets/index.html
                    while (true) {
                        try {

                            Socket clientSocket = serverSocket.accept();
                            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

                            Log.d(TAG, "server create a ServerSocket");

                            inputLine = in.readLine();
                            if (inputLine != null) {
                                String server_message = inputLine;
                                String[] message_contents = server_message.split(",");

                                String type = message_contents[0];
                                Log.d(TAG, "Request from " + message_contents[1] + " for " + message_contents[0]);

                                if (type.equals("NEW_NODE")) {


                                    try {
                                        new_id = genHash(String.valueOf((Integer.parseInt(message_contents[1]) / 2)));

                                    } catch (NoSuchAlgorithmException e) {
                                        e.printStackTrace();
                                    }

                                    if (prev_id.compareTo(my_id) < 0) {
                                        Log.d(TAG,"entered-1");
                                        if (new_id.compareTo(prev_id) > 0 && new_id.compareTo(my_id) <= 0) {
                                            Log.d(TAG,"entered-2");
                                            //String new_join_message = "NEW_NODE"+","+my_port+","+prev_port+","+succ_port+",\n";
                                            String new_update = "UPDATE" + "," + my_port + "," + "" + "," + message_contents[1] + ",\n";
                                            ClientTask(new_update, prev_port,Storage);
                                            String new_reply = "REPLY" + "," + my_port + "," + prev_port + "," + my_port + ",\n";
                                            ClientTask(new_reply, message_contents[1],Storage);
                                            prev_port = message_contents[1];
                                            prev_id = new_id;
                                        } else {
                                            Log.d(TAG,"entered-3");
                                            to_port = succ_port;
                                            ClientTask(server_message, succ_port,Storage);

                                        }
                                    } else if (prev_id.compareTo(my_id) > 0) {

                                        Log.d(TAG,"entered-4");
                                        if (new_id.compareTo(my_id) <= 0 || new_id.compareTo(prev_id) > 0) {
                                            Log.d(TAG,"entered-5");
                                            //String new_join_message = "NEW_NODE"+","+my_port+","+prev_port+","+succ_port+",\n";
                                            String new_update = "UPDATE" + "," + my_port + "," + "" + "," + message_contents[1] + ",\n";
                                            ClientTask(new_update, prev_port,Storage);
                                            String new_reply = "REPLY" + "," + my_port + "," + prev_port + "," + my_port + ",\n";
                                            ClientTask(new_reply, message_contents[1],Storage);
                                            prev_port = message_contents[1];
                                            prev_id = new_id;

                                        } else {
                                            Log.d(TAG,"entered-6");
                                            to_port = succ_port;
                                            ClientTask(server_message, succ_port,Storage);
                                        }

                                    } else if (prev_id.compareTo(my_id) == 0) {
                                        Log.d(TAG,"entered-7");
                                        String new_reply = "REPLY" + "," + my_port + "," + prev_port + "," + my_port + ",\n";
                                        ClientTask(new_reply, message_contents[1],Storage);
                                        prev_port = message_contents[1];
                                        prev_id = new_id;
                                        succ_port = message_contents[1];
                                        succ_id = new_id;
                                    }

                                    Log.d(TAG, " After New node Request from " + message_contents[1] + " myport " + my_port + " prevport" + prev_port + " succport " + succ_port);
                                    Log.d(TAG, " After New node Request from " + message_contents[1] + " myid " + my_id + " previd" + prev_id + " succid " + succ_id);
                                } else if (type.equals("REPLY")) {

                                    try {
                                        prev_port = message_contents[2];
                                        prev_id = genHash(String.valueOf((Integer.parseInt(message_contents[2]) / 2)));
                                        succ_port = message_contents[3];
                                        succ_id = genHash(String.valueOf((Integer.parseInt(message_contents[3]) / 2)));


                                    } catch (NoSuchAlgorithmException e) {
                                        e.printStackTrace();
                                    }

                                    Log.d(TAG, " After reply from " + message_contents[1] + " myport " + my_port + " prevport" + prev_port + " succport " + succ_port);
                                    Log.d(TAG, " After reply from " + message_contents[1] + " myid " + my_id + " previd" + prev_id + " succid " + succ_id);


                                } else if (type.equals("UPDATE")) {

                                    try {

                                        succ_port = message_contents[3];
                                        succ_id = genHash(String.valueOf((Integer.parseInt(message_contents[3]) / 2)));


                                    } catch (NoSuchAlgorithmException e) {
                                        e.printStackTrace();
                                    }

                                    Log.d(TAG, " After update of prev from " + message_contents[1] + " myport " + my_port + " prevport" + prev_port + " succport " + succ_port);
                                    Log.d(TAG, " After update  of prev from " + message_contents[1] + " myid " + my_id + " previd" + prev_id + " succid " + succ_id);


                                } else if (type.equals("INSERT")) {
                                    Log.d(TAG, " During insert in my port " + my_port + " prevport is" + prev_port + " succport is  " + succ_port);
                                    ContentValues ins_mes = new ContentValues();
                                    ins_mes.put("key", message_contents[1]);
                                    ins_mes.put("value", message_contents[4]);
                                    insert(myUri, ins_mes);

                                } else if (type.equals("QUERY")) {
                                    Log.d(TAG,"stage1 "+ server_message);
                                    if (my_port.equals(message_contents[2])) {
                                        Log.d(TAG,"stage2 "+ server_message);
                                        local_message = message_contents[4];
                                        Log.d(TAG,"stage3 "+ local_message);
                                        isComplete = true;

                                    } else {
                                        //String Query_One_m = "QUERY"+","+selection+","+my_port+","+""+","+""+",\n";
                                        Log.d(TAG,"stage4 "+ server_message);
                                        try {
                                            new_id = genHash(message_contents[1]);
                                        } catch (NoSuchAlgorithmException e) {
                                            e.printStackTrace();
                                        }
                                        if (prev_id.compareTo(my_id) < 0) {
                                            Log.d(TAG,"stage5 ");
                                            if (new_id.compareTo(prev_id) > 0 && new_id.compareTo(my_id) <= 0) {
                                                Log.d(TAG,"stage6 ");
                                                local_Query = query_one(message_contents[1]);
                                                String Query_One_m = "QUERY" + "," + message_contents[1] + "," + message_contents[2] + "," + "" + "," + local_Query + ",\n";
                                                Log.d(TAG,"stage7 "+Query_One_m);
                                                ClientTask(Query_One_m, succ_port,Storage);
                                            } else {
                                                ClientTask(server_message, succ_port,Storage);
                                                Log.d(TAG,"stage8 ");

                                            }
                                        } else if (prev_id.compareTo(my_id) > 0) {
                                            Log.d(TAG,"stage9 ");

                                            if (new_id.compareTo(my_id) <= 0 || new_id.compareTo(prev_id) > 0) {
                                                Log.d(TAG,"stage10 ");
                                                local_Query = query_one(message_contents[1]);
                                                String Query_One_m = "QUERY" + "," + message_contents[1] + "," + message_contents[2] + "," + "" + "," + local_Query + ",\n";
                                                Log.d(TAG,"stage11 "+Query_One_m);
                                                ClientTask(Query_One_m, succ_port,Storage);
                                            } else {
                                                ClientTask(server_message, succ_port,Storage);
                                                Log.d(TAG,"stage12 ");

                                            }
                                        }
                                        //maybe handle but not required where pre is equrla to node since it done on query part

                                    }

                                } else if (type.equals("DUMP")) {
                                    if (my_port.equals(message_contents[1])) {

                                        global_message = message_contents[4];
                                        Log.d(TAG,global_message);
                                        isComplete = true;
                                    } else {

                                        try {
                                            for (String file_N1 : getContext().fileList()) {
                                                inputStream1 = getContext().openFileInput(file_N1);
                                                BufferedReader in1 = new BufferedReader(new InputStreamReader(inputStream1));
                                                Q_values1 = in1.readLine();
                                                message_contents[4] += file_N1 + ":" + Q_values1 + "&";
                                                //Storage.put(file_N1,Q_values1);

                                            }
                                        } catch (FileNotFoundException e) {
                                            e.printStackTrace();
                                        } catch (IOException e) {
                                            e.printStackTrace();
                                        }

                                        String Dump_m1 = "DUMP" + "," + message_contents[1] + "," + "" + "," + "" + "," + message_contents[4] + ",\n";
                                        ClientTask(Dump_m1, succ_port,Storage);
                                        //Storage.clear();


                                    }

                                } else if (type.equals("DELETE")) {
                                    //String Delete_m = "DELETE"+","+"*"+","+my_port+","+""+","+""+",\n";
                                    if (my_port.equals(message_contents[2])) {

                                        //done

                                    } else {
                                        if (message_contents[1].equals("*")) {

                                            for (String file_delete_local : getContext().fileList()) {
                                                getContext().deleteFile(file_delete_local);
                                            }
                                            String Delete_m = "DELETE" + "," + "*" + "," + message_contents[2] + "," + "" + "," + "" + ",\n";
                                            ClientTask(Delete_m, succ_port,Storage);

                                        } else {
                                            try {
                                                new_id = genHash(message_contents[1]);
                                            } catch (NoSuchAlgorithmException e) {
                                                e.printStackTrace();
                                            }
                                            if (prev_id.compareTo(my_id) < 0) {
                                                if (new_id.compareTo(prev_id) > 0 && new_id.compareTo(my_id) <= 0) {
                                                    getContext().deleteFile(message_contents[1]);
                                                } else {
                                                    String Delete_local = "DELETE" + "," + message_contents[1] + "," + message_contents[2] + "," + "" + "," + "" + ",\n";
                                                    ClientTask(Delete_local, succ_port,Storage);

                                                }
                                            } else if (prev_id.compareTo(my_id) > 0) {

                                                if (new_id.compareTo(my_id) <= 0 || new_id.compareTo(prev_id) > 0) {
                                                    getContext().deleteFile(message_contents[1]);
                                                } else {
                                                    String Delete_local = "DELETE" + "," + message_contents[1] + "," + message_contents[2] + "," + "" + "," + "" + ",\n";
                                                    ClientTask(Delete_local, succ_port,Storage);

                                                }
                                            }


                                        }

                                    }

                                }

                            }

                            //if (inputLine != null) {
                            //    publishProgress(inputLine);
                            //}
                            //in.close();
                            //clientSocket.close();

                        } catch (UnknownHostException e) {
                            Log.e(TAG, "ServerTask UnknownHostException");
                            break;
                        } catch (IOException e) {
                            Log.e(TAG, "ServerTask socket IOException");
                            break;
                        }

                    }
                }
            }).start();
            /*
            * TODO: Fill in your server code that receives messages and passes them
             * to onProgressUpdate().

             */

            return null;
        }




        private Void ClientTask(final String msgs,final String sendport,final Map<String, String > Storage_map) {
            new Thread(new Runnable() {
                public void run() {
                    try {

                        String port = msgs;


                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(sendport));
                        Log.d(TAG, "client create a ServerSocket "+ sendport);

                        String msgToSend = msgs;
                        Log.d(TAG,"message is " + msgToSend);


                /* *  TODO: Fill in your client code that sends out a message.

                 */
                        //the below has been taken from https://docs.oracle.com/javase/tutorial/networking/sockets/index.html

                        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                        out.println(msgToSend);
                        out.flush();


                    } catch (UnknownHostException e) {
                        Log.e(TAG, "ClientTask UnknownHostException");
                    } catch (IOException e) {
                        Log.e(TAG, "ClientTask socket IOException");
                    }
                }
            }).start();
         return null;
        }


    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }
}
