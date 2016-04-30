#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <unistd.h>
#include <time.h>


#include <shm.h>



int MSGQUE_Init(int key)
{
	int msgque_id;

	msgque_id = msgget(key, 0666 | IPC_CREAT);

	if(msgque_id == -1){
		perror("msgget\n");
		return -1;
	}

	return msgque_id;
}





int MSGQUE_Send(int msgid, MSG_QUE_BODY *msgbody)
{
	return msgsnd(msgid, msgbody, sizeof(msgbody->msg), IPC_NOWAIT);
}



int MSGQUE_Recv(int msgid, MSG_QUE_BODY *msgbody)
{
	return msgrcv(msgid, msgbody, sizeof(msgbody->msg), msgbody->mtype, 0);
}


int MSGQUE_Rpc_Syncall2dp(int msgid, MSG_QUE_BODY *msgbody_snd, MSG_QUE_BODY *msgbody_rcv)
{
    if(MSGQUE_Send(msgid, msgbody_snd) < 0)
    {
        printf("MSGQUE_Rpc_Syncall2dp send failed\n");
        return -1;
    }


    if(MSGQUE_Recv(msgid, msgbody_rcv) < 0)
    {
        printf("msg rpc syncall recv failed\n");
        return -1;
    }

    return 0;
}


