#include <ncurses.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <dirent.h>

void print_time(WINDOW *win) {
    time_t rawtime;
    struct tm *timeinfo;
    char buffer[80];

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    mvwprintw(win, 0, 0, "TIME: %s", buffer);
}



void print_file_content(WINDOW *win, const char *filename, int y, int x, int width, int height) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        return;
    }

    int col = getmaxx(win);
    int line = getmaxy(win);
    int current_y = y;
    int current_x = x;
    char lines[col];
    while (fgets(lines, sizeof(lines), file)) {
        if (current_y >= height) {
            break; // 超过窗口高度限制，停止打印
        }
        if (current_x + strlen(lines) > x + width) {
            mvwprintw(win, current_y, current_x, "%s", lines);
            current_y += 1; // 超过窗口宽度限制，换行继续打印
            current_x = x;
            lines[0] = '\0';
        } else {
            mvwprintw(win, current_y, current_x, "%s", lines);
            current_y += 1;
            current_x = x;
            lines[0] = '\0';
        }
    }

    fclose(file);
}




    int gcount = 0;

void show_menu(WINDOW *win) {
    int col = getmaxx(win);
    int line = getmaxy(win);
    print_time(win);
    print_file_content(win, "/usr/local/openresty/nginx/conf/waf/config.lua",7,0,line,col);
    mvprintw(0, (col - strlen(".\\   ||   //   ||    ||FFFF  t     eee  sssss  t   .")) / 2, "\\\\   ||   //   ||    ||FFFF  t     eee   sss   t   ");
    mvprintw(1, (col - strlen(". \\  ||  //   //\\   ||     ttttt e   e s     ttttt.")) / 2, " \\\\  ||  //   //\\\\   ||     ttttt e   e s     ttttt");
    mvprintw(2, (col - strlen(".  \\//\\//   //  \\  ||FFFF  t    eeeee sssss  t   .")) / 2, " \\\\//\\\\//   //  \\\\  ||FFFF  t    eeeee  sss   t   ");
    mvprintw(3, (col - strlen(".   ||  ||   //AAAA\\ ||      t    e         s  t   .")) / 2, "   ||  ||   //AAAA\\\\ ||      t    e         s  t   ");
    mvprintw(4, (col - strlen(".   ||  ||  //      \\||      tttt  eee  sssss  tttt.")) / 2, "   ||  ||  //      \\\\||       ttt  eee   sss    ttt");
}

void show_logs_page(WINDOW *win, int selected1) {
    int col = getmaxx(win);
    int line = getmaxy(win);
    struct dirent *entry;
    int file_count = 0;
    int max_files = 10; // 最大显示文件数
    char files[max_files][256];

    DIR *dir = opendir("/tmp");
    if (dir == NULL) {
        return;
    }

    while ((entry = readdir(dir)) != NULL && file_count < max_files) {
        if (entry->d_type == DT_REG) {
            strncpy(files[file_count], entry->d_name, sizeof(files[file_count]));
            file_count++;
        }
        gcount = file_count;
        }
    closedir(dir);

    int y = 0;
    for (int i = 0; i < file_count; i++) {
        if (i == selected1) {
            wattron(win, A_REVERSE); // 设置高亮属性
        }
        mvwprintw(win, y++, 0, "%s", files[i]);
        wattroff(win, A_REVERSE); // 取消高亮属性
        if (selected1 >= 0 && selected1 < file_count) {
            char filename[256];
            snprintf(filename , sizeof(filename) , "/tmp/%s", files[selected1]);
            print_file_content(win, filename, 8, 0, 25, col);

            char file_path[256];
            sprintf(file_path, "/tmp/%s", files[selected1]);
            FILE *file = fopen(file_path, "r");
            if (file == NULL) {
            mvprintw(3, (col - strlen("not such file or wrong dir")) / 2, "not such file or wrong dir");
            } else {
                char targetStr[] = "Deny_URL"; // 要统计的字符串
                char targetStr1[] = "CC_Attack";
                char targetStr2[] = "White_IP";
                char targetStr3[] = "BlackList_IP";
                char targetStr4[] = "Deny_Cookie";
                char targetStr5[] = "Deny_URL_Args";
                char targetStr6[] = "Deny_USER_AGENT";
                int count = 0; // 计数器
                int count1 = 0;
                int count2 = 0;
                int count3 = 0;
                int count4 = 0;
                int count5 = 0;
                int count6 = 0;

                char lineBuffer[1024];
                while (fgets(lineBuffer, sizeof(lineBuffer), file) != NULL) {
                if (strstr(lineBuffer, targetStr) != NULL) {
                        count++;
                }
                if (strstr(lineBuffer, targetStr1) != NULL) {
                        count1++;
                }
                if (strstr(lineBuffer, targetStr2) != NULL) {
                        count2++;
                }
                if (strstr(lineBuffer, targetStr3) != NULL) {
                        count3++;
                }
                if (strstr(lineBuffer, targetStr4) != NULL) {
                        count4++;
                }
                if (strstr(lineBuffer, targetStr5) != NULL) {
                        count5++;
                }
                if (strstr(lineBuffer, targetStr6) != NULL) {
                        count6++;
                }
                }
                int row = 0;
                mvprintw(row, 35 , "URL_ATTACK------%d次", count);
                mvprintw(row + 1, 35 , "CC_Attack-------%d次", count1);
                mvprintw(row + 2, 35 , "White_IP--------%d次", count2);
                mvprintw(row + 3, 35 , "BlackList_IP----%d次", count3);
                mvprintw(row + 4, 35 , "Deny_Cookie-----%d次", count4);
                mvprintw(row + 5, 35 , "Deny_URL_Args---%d次", count5);
                mvprintw(row + 6, 35 , "Deny_USER_AGENT-%d次", count6);
                fclose(file);
                }
                }
        }
}

void draw_buttons(WINDOW *win) {
    mvwprintw(win, LINES - 2, 0, "(S)etting view | (L)ogs view | (M)enu view | (Q)uit");
}

void show_setting_page(WINDOW *win, int selected) {
    int col = getmaxx(win);
    int line = getmaxy(win);

    struct dirent *entry;
    int file_count = 0;
    int max_files = 10; // 最大显示文件数
    char files[max_files][256];

    DIR *dir = opendir("/usr/local/openresty/nginx/conf/waf/rule-config");
    if (dir == NULL) {
        return;
    }

    while ((entry = readdir(dir)) != NULL && file_count < max_files) {
        if (entry->d_type == DT_REG) {
            strncpy(files[file_count], entry->d_name, sizeof(files[file_count]));
            file_count++;
        }
        gcount = file_count;
        }
    closedir(dir);

    int y = 0;
    for (int i = 0; i < file_count; i++) {
        if (i == selected) {
            wattron(win, A_REVERSE); // 设置高亮属性
        }
        mvwprintw(win, y++, 0, "%s", files[i]);
        wattroff(win, A_REVERSE); // 取消高亮属性
        if (selected >= 0 && selected < file_count) {
            char filename[256];
            snprintf(filename , sizeof(filename) , "/usr/local/openresty/nginx/conf/waf/rule-config/%s", files[selected]);
            mvprintw( 9, 0,"/usr/local/openresty/nginx/conf/waf/rule-config/%s", files[selected]);
            print_file_content(win, filename, 11, 0, line, col);
        }
    }
}

int main() {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);

    int selected = 0;
    int selected1 = 0;

    int file_count;
    int ch;
    int current_page = 0;
    const char *pages[] = {"menu", "logs", "setting"};
    scrollok(stdscr, TRUE);
    keypad(stdscr, TRUE);

    while (1) {
        clear();
        draw_buttons(stdscr);

        if (current_page == 0) {
            show_menu(stdscr);
        } else if (current_page == 1) {
            show_logs_page(stdscr, selected1);
        } else if (current_page == 2) {
            show_setting_page(stdscr, selected);
        }

        refresh();

        ch = getch();
        if (ch == 'q' || ch == 'Q') {
            break;
        } else if (ch == 'm' || ch == 'M') {
            current_page = 0;
        } else if (ch == 'l' || ch == 'L') {
            current_page = 1;
        } else if (ch == 's' || ch == 'S') {
            current_page = 2;
        }else if (ch == KEY_DOWN || ch == KEY_UP) {
            if (current_page == 2){
                if (ch == KEY_UP){
                    selected = (selected - 1 + gcount) % gcount;
                }else if(ch == KEY_DOWN){
                    selected = (selected + 1) % gcount;
                }else if(ch == 'i'){
                    system("reboot");
                }
                show_setting_page(stdscr, selected);
                }else if (current_page == 1){
                    if (ch == KEY_UP){
                        selected1 = (selected1 - 1 + gcount) % gcount;
                    }else if(ch == KEY_DOWN){
                        selected1 = (selected1 + 1) % gcount;
                    }
                    show_logs_page(stdscr, selected1);
        }
        }
    }

    endwin();
    return 0;
}


