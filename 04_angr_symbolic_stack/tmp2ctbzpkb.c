#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define USERDEF0 2997776385
#define USERDEF1 1966343970

char msg[] = "";

void print_msg() {
  printf("%s", msg);
}

uint32_t complex_function0(uint32_t value) {
  value ^= 2533711732;value ^= 2593354591;value ^= 2343946690;value ^= 995143788;value ^= 3918799375;value ^= 2793389223;value ^= 3760967890;value ^= 2831565273;value ^= 1820446797;value ^= 980611347;value ^= 3230278687;value ^= 209927687;value ^= 2280613315;value ^= 2051206487;value ^= 4004020839;value ^= 3859445670;value ^= 1872572178;value ^= 170950821;value ^= 3677808046;value ^= 1437212780;value ^= 2686921896;value ^= 3847214437;value ^= 1299307166;value ^= 2364791306;value ^= 510873734;value ^= 1470206620;value ^= 3165490505;value ^= 2564832072;value ^= 539405512;value ^= 1391856955;value ^= 616548599;value ^= 329054243;
  return value;
}

uint32_t complex_function1(uint32_t value) {
  value ^= 3719196317;value ^= 2979048246;value ^= 968728659;value ^= 56966325;value ^= 1635704867;value ^= 164594016;value ^= 248282231;value ^= 2222561507;value ^= 3793834468;value ^= 4251205034;value ^= 882375839;value ^= 1827536944;value ^= 1749698508;value ^= 782058120;value ^= 2883770482;value ^= 2928618623;value ^= 3039571705;value ^= 314028640;value ^= 3510754512;value ^= 515637315;value ^= 1799264849;value ^= 2338999872;value ^= 2550244840;value ^= 2329154939;value ^= 3310465120;value ^= 3371939078;value ^= 2989903830;value ^= 3679244865;value ^= 4244655143;value ^= 917105375;value ^= 2349674148;value ^= 2722154001;
  return value;
}

void handle_user() {
  uint32_t user_int0;
  uint32_t user_int1;
  scanf("%u %u", &user_int0, &user_int1);
  user_int0 = complex_function0(user_int0);
  user_int1 = complex_function1(user_int1);
  if ((user_int0 ^ USERDEF0) || (user_int1 ^ USERDEF1)) {
    printf("Try again.\n");
  } else {
    printf("Good Job.\n");
  }
}

int main(int argc, char* argv[]) {
  //print_msg();
  printf("Enter the password: ");
  handle_user();
}