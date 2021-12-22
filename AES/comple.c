printf("== DECRYPT round ==\n");
    for(i = 0; i < Nr; i++) { // Nr
      printf("\n== DECRYPT round %d ==\n", i+1);
      SubBytes(state, mode);
      //printf("\n== SubBytes ==\n");
      //print_state(state);
      ShiftRows(state, mode);
      //printf("\n== ShiftRows ==\n");
      //print_state(state);
      AddRoundKey(state, roundKey, index);
      //printf("\n== AddRoundKey ==\n");
      //print_state(state);
      if (i != 9) {
        MixColumns(state, mode);
        //printf("\n== MixColumns ==\n");
        //print_state(state);
      }
      index += corr;
    }

printf("\n== DECRYPT round ==\n");
    for(i = 0; i < Nr; i++) { // Nr
      printf("\n== DECRYPT round %d ==\n", i+1);
      SubBytes(state, mode);
      printf("\n== SubBytes ==\n");
      print_state(state);
      ShiftRows(state, mode);
      printf("\n== ShiftRows ==\n");
      print_state(state);
      /*
      if (i != 9) {
        MixColumns(state, mode);
        //printf("\n== MixColumns ==\n");
        //print_state(state);
      }
      */

      if (i != 9) {

      

      uint8_t tmp_RND[BLOCKLEN];
      uint8_t *p;

      for (j = 0; j < Nk; j++) {
        p = (uint8_t *)(roundKey + j + 4 * index);
        tmp_RND[j * 4] = p[0];
        tmp_RND[j * 4 + 1] = p[1];
        tmp_RND[j * 4 + 2] = p[2];
        tmp_RND[j * 4 + 3] = p[3];
      }

      MixColumns(tmp_RND, mode);

      /*
      for (j = 0; j < BLOCKLEN; j++) {
        state[j] = state[j] ^ tmp_RND[j];
      }
      */

      MixColumns(state, mode);
      
      for (j = 0; j < BLOCKLEN; j++) {
        state[j] = state[j] ^ tmp_RND[j];
      }
      }

      /*

      MixColumns(tmp_RND, mode);

      uint32_t tmp_RNDkey[RNDKEYSIZE];

      for (j = 0; j < Nk; j++) {
        p = (uint8_t *)(roundKey + j + 4 * index);
        p[0] = tmp_RND[j * 4];
        p[1] = tmp_RND[j * 4 + 1];
        p[2] = tmp_RND[j * 4 + 2];
        p[3] = tmp_RND[j * 4 + 3];
      }

      AddRoundKey(state, tmp_RNDkey, index);
      */

      AddRoundKey(state, roundKey, index);
      printf("\n== AddRoundKey ==\n");
      print_state(state);

      index += corr;
    }