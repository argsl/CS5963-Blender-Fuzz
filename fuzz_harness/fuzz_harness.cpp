#include "MEM_guardedalloc.h"

#include "BKE_appdir.hh"
#include "BKE_blender.hh"
#include "BKE_callbacks.hh"
#include "BKE_context.hh"
#include "BKE_global.hh"
#include "BKE_idtype.hh"
#include "BKE_image.hh"
#include "BKE_layer.hh"
#include "BKE_main.hh"
#include "BKE_modifier.hh"
#include "BKE_node.hh"
#include "BKE_scene.hh"
#include "BKE_report.hh"
#include "BKE_vfont.hh"

#include "BLF_api.hh"

#include "BLI_listbase.h"
#include "BLI_path_utils.hh"
#include "BLI_threads.h"

#include "BLO_readfile.hh"

#include "DEG_depsgraph.hh"
#include "DEG_depsgraph_build.hh"

#include "DNA_genfile.h" /* for DNA_sdna_current_init() */
#include "DNA_windowmanager_types.h"

#include "IMB_imbuf.hh"

#include "ED_datafiles.h"

#include "RNA_define.hh"

#include "CLG_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  // for isatty()

#define MAX_FILE_SIZE (1024 * 1024 * 10)

__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
    BlendFileData *bfile = NULL;

    CLG_init();
    BLI_threadapi_init();
  
    DNA_sdna_current_init();
    BKE_blender_globals_init();
  
    BKE_idtype_init();
    BKE_appdir_init();
    IMB_init();
    BKE_modifier_init();
    DEG_register_node_types();
    RNA_init();
    blender::bke::node_system_init();
    BKE_callback_global_init();
    BKE_vfont_builtin_register(datatoc_bfont_pfb, datatoc_bfont_pfb_size);
    BLF_init();

    G.background = true;
    G.factory_startup = true;

    while (__AFL_LOOP(10000)) { 
        BKE_blender_globals_clear();
        BKE_blender_globals_init();
        
        if (bfile) {
            BLO_blendfiledata_free(bfile);
            bfile = NULL;
        }
        
        unsigned char *buffer = __AFL_FUZZ_TESTCASE_BUF;
        int len = __AFL_FUZZ_TESTCASE_LEN;
        
        ReportList reports;
        BKE_reports_init(&reports, RPT_STORE);
        bfile = BLO_read_from_memory(buffer, len, BLO_READ_SKIP_NONE, &reports);
        
        if (!bfile) {
            fprintf(stderr, "Failed to load fuzzed blend file (%d bytes).\n", len);
            Report *report;
            for (report = (Report *)reports.list.first; report; report = report->next) {
                fprintf(stderr, "Blender Error: %s\n", report->message);
            }
            BKE_reports_clear(&reports);
            BKE_reports_free(&reports);
            continue;
        }
        else {
            BLO_blendfiledata_free(bfile);
            bfile = NULL;
        }
        
        BKE_reports_clear(&reports);
        BKE_reports_free(&reports);
    }

    BKE_blender_globals_clear();
    return 0;
}
