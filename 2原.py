from datetime import datetime,timedelta
import requests
import random
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
import json

custom_base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
custom_base64_dict = {i: j for i, j in enumerate(custom_base64_table)}
def custom_base64_encode(data):
    # 使用标准的 base64 编码
    standard_encoded = base64.b64encode(data).decode('utf-8')
    
    # 替换为自定义的 Base64 字符
    custom_encoded = []
    for c in standard_encoded:
        if c.isupper():
            custom_encoded.append(custom_base64_table[ord(c) - 65])
        elif c.islower():
            custom_encoded.append(custom_base64_table[ord(c) - 97 + 26])
        elif c.isdigit():
            custom_encoded.append(custom_base64_table[ord(c) - 48 + 52])
        elif c == '+':
            custom_encoded.append(custom_base64_table[62])  # 对应 '+' 的替代字符
        elif c == '/':
            custom_encoded.append(custom_base64_table[63])  # 对应 '/' 的替代字符
        else:
            # 可以选择忽略或处理不在字符集中的字符
            print(f"Warning: Ignoring character '{c}'")

    return ''.join(custom_encoded)
def custom_base64_decode(custom_encoded_str):
    
    # 反向映射字符串到标准 Base64
    standard_encoded_str = ''.join(custom_base64_table[custom_base64_dict[char]] if char in custom_base64_dict else char for char in custom_encoded_str)

    # 添加必要的填充 '=' 符号
    padding_needed = (4 - len(standard_encoded_str) % 4) % 4
    standard_encoded_str += '=' * padding_needed

    # 解码为原始字节数据
    decoded_data = base64.b64decode(standard_encoded_str)
    return decoded_data


def decrypt_aes_ecb(base64_encoded_data, key):
    # 解码 Base64
    encrypted_data = custom_base64_decode(base64_encoded_data)
    
    # 创建 AES ECB 解密器
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    
    # 解密数据
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    
    return decrypted_data.decode('utf-8')
def encrypt_aes_ecb(plain_text, key):
    # 创建 AES ECB 加密器
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    
    # 加密数据并进行 Base64 编码
    encrypted_data = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    base64_encoded_data = custom_base64_encode(encrypted_data)
    
    return base64_encoded_data
def login_get_key(timestamp):
    # 假设传入的时间戳为字符串形式
    a1 = str(timestamp)

    # 根据 C 代码逻辑提取部分字符串
    dest = a1[2:5]  # 从索引 2 开始提取 3 个字符
    nptr = a1[4:8]  # 从索引 4 开始提取 4 个字符
    v2 = a1[-1]     # 最后一个字符

    # 将 dest 转换为整数
    v1 = int(dest)
    # 将 nptr 转换为整数
    n = int(nptr)

    # 计算 v3
    v3 = v1 - n

    # 计算 v4 的绝对值
    v4 = abs(v3)

    # 计算 v5，左移 v4 位
    v5 = v4 << int(v2)

    # 拼接字符串
    fixed_string = "402881ea7c39c5d5017c39d143a8062b"
    final_key = f"{v5}{fixed_string}"

    return final_key[:16]
def getRunningKey(Id, SchoolId):
    # 读取状态寄存器（模拟） 
    # 从 Id 和 SchoolId 中提取相关信息
    dest = Id[3:6]  # 从 Id 的第4个字符开始提取3个字符
    v14 = SchoolId[4:7]  # 从 SchoolId 的第5个字符开始提取3个字符
    v13 = Id[9:12]  # 从 Id 的第10个字符开始提取3个字符
    
    # 生成动态密钥
    v5 = "3e0783d6891a4a3e9521dcb6bb341560"  # 固定字符串
    # 计算最终字符串的长度
    combined_key = f"{dest}{v14}{v13}{v5}"  # 拼接字符串

    # 返回最终的密钥
    return combined_key[:16]

def encode(str):
    solt="itauVfnexHiRigZ6"
    a = hashlib.sha1((str+solt).encode("utf-8")).hexdigest()
    return a
def encodeuser(username,password):
    solt="itauVfnexHiRigZ6"
    a=hashlib.sha1((username+password+"1"+solt).encode("utf-8")).hexdigest()
    return a
def getinfo(mileage,pyd_dict):

    Key=getRunningKey(pyd_dict["id"],pyd_dict["schoolId"])
    print("跑步Key:",Key)

    info={"appVersion":"3.10.0","avePace":215686.0,"calorie":61,"deviceType":"google Pixel 6 Pro","effectiveMileage":1.0202,"effectivePart":1,"endTime":"2024-09-20 06:30:52","gpsMileage":1.0202,"keepTime":220,"limitationsGoalsSexInfoId":"402888da7c3a16bb017c3a17044e000f","oct":"","paceNumber":0,"paceRange":0,"routineLine":[{"latitude":30.82694,"longitude":104.183186},{"latitude":30.826939,"longitude":104.183205},{"latitude":30.826938260573808,"longitude":104.1830688177567},{"latitude":30.82695613516029,"longitude":104.18307168329491},{"latitude":30.8269446692772,"longitude":104.18309839320607},{"latitude":30.826916297623377,"longitude":104.18310159591135},{"latitude":30.826896783277313,"longitude":104.18321138142083},{"latitude":30.826876092750247,"longitude":104.18325404136438},{"latitude":30.826895393871652,"longitude":104.18330777272061},{"latitude":30.826895908948195,"longitude":104.18336995754834},{"latitude":30.826884548312645,"longitude":104.18341009267479},{"latitude":30.826874552196422,"longitude":104.18345900163719},{"latitude":30.82687178995983,"longitude":104.1835187908292},{"latitude":30.826861147533112,"longitude":104.18356553381811},{"latitude":30.826851785455812,"longitude":104.18362328652178},{"latitude":30.826837656387195,"longitude":104.18367259464624},{"latitude":30.826825644612722,"longitude":104.1837240090006},{"latitude":30.826810866014693,"longitude":104.18377288793457},{"latitude":30.826783165369037,"longitude":104.18382442136915},{"latitude":30.826800791294332,"longitude":104.1838968084693},{"latitude":30.82681985123998,"longitude":104.18395123884775},{"latitude":30.826817206917077,"longitude":104.1840014859421},{"latitude":30.8268185698403,"longitude":104.18405984827419},{"latitude":30.826823847665047,"longitude":104.18412757355166},{"latitude":30.826827622319353,"longitude":104.18418033639917},{"latitude":30.826821017801624,"longitude":104.18423496533792},{"latitude":30.826806227340413,"longitude":104.18428495247244},{"latitude":30.82680699490615,"longitude":104.18433526976608},{"latitude":30.82680246270654,"longitude":104.1843892999916},{"latitude":30.82679241754761,"longitude":104.18443787004034},{"latitude":30.826796092550033,"longitude":104.18449048332276},{"latitude":30.82678381881636,"longitude":104.18454305594715},{"latitude":30.82677699394487,"longitude":104.18458704465692},{"latitude":30.826778352104697,"longitude":104.18463728227995},{"latitude":30.82678058023318,"longitude":104.18468780943802},{"latitude":30.826775652010774,"longitude":104.18473964387726},{"latitude":30.82677244768758,"longitude":104.184789891344},{"latitude":30.8267708769933,"longitude":104.18484410163265},{"latitude":30.826773444567767,"longitude":104.18489507809059},{"latitude":30.826769034497215,"longitude":104.18494812044882},{"latitude":30.826758174239075,"longitude":104.1849993358834},{"latitude":30.826756151632296,"longitude":104.18504906449667},{"latitude":30.82675006556612,"longitude":104.18509946171562},{"latitude":30.826748001913746,"longitude":104.18514976931819},{"latitude":30.826745143420595,"longitude":104.18519704247495},{"latitude":30.82674065184279,"longitude":104.18525095340857},{"latitude":30.82673712671196,"longitude":104.18530166029214},{"latitude":30.82673170861607,"longitude":104.18534253512846},{"latitude":30.826726478135363,"longitude":104.1853902175217},{"latitude":30.82671704393203,"longitude":104.1854277782755},{"latitude":30.82671181504488,"longitude":104.1854746122669},{"latitude":30.82670633966787,"longitude":104.18551946988829},{"latitude":30.826697073363285,"longitude":104.18556369850225},{"latitude":30.826686454019093,"longitude":104.18560918477273},{"latitude":30.826677705564208,"longitude":104.18565476099114},{"latitude":30.826659864101508,"longitude":104.18569378877221},{"latitude":30.826636304318164,"longitude":104.18573018111529},{"latitude":30.82660719020318,"longitude":104.18575090185125},{"latitude":30.82657335269194,"longitude":104.18576114152201},{"latitude":30.82653803264278,"longitude":104.18576140934779},{"latitude":30.82650504614739,"longitude":104.18575498950786},{"latitude":30.826474460077616,"longitude":104.18574360885043},{"latitude":30.826446205018748,"longitude":104.18572692799447},{"latitude":30.826413835391246,"longitude":104.18570604462863},{"latitude":30.826379540143645,"longitude":104.18568764663134},{"latitude":30.82634349469963,"longitude":104.18566882932114},{"latitude":30.826302130434822,"longitude":104.1856477658692},{"latitude":30.826265640172707,"longitude":104.18562599395064},{"latitude":30.826229982208016,"longitude":104.18560867393273},{"latitude":30.82619358697028,"longitude":104.18559509703483},{"latitude":30.826153673413963,"longitude":104.18557954358756},{"latitude":30.826116811732714,"longitude":104.18556389047096},{"latitude":30.826077395342875,"longitude":104.18555003394737},{"latitude":30.826039818587013,"longitude":104.18552603607466},{"latitude":30.826002627575388,"longitude":104.18550992379208},{"latitude":30.825967696919633,"longitude":104.18549430072461},{"latitude":30.825926181070212,"longitude":104.18547407577098},{"latitude":30.82588109283855,"longitude":104.18545952027036},{"latitude":30.825837242625845,"longitude":104.18544097214242},{"latitude":30.82579518080367,"longitude":104.18542384150754},{"latitude":30.82575344969066,"longitude":104.18541187143968},{"latitude":30.825709008390913,"longitude":104.1854046325782},{"latitude":30.82565808842102,"longitude":104.18540560836176},{"latitude":30.82560786698697,"longitude":104.18539670227885},{"latitude":30.82555975489716,"longitude":104.18539423450392},{"latitude":30.825515695216442,"longitude":104.18538078703521},{"latitude":30.8254777636558,"longitude":104.18537565462776},{"latitude":30.825438963918213,"longitude":104.1853638244497},{"latitude":30.825398773381362,"longitude":104.18534112412371},{"latitude":30.825360308454915,"longitude":104.18532677857536},{"latitude":30.825307009963566,"longitude":104.18532623702504},{"latitude":30.825248973956818,"longitude":104.18532836036538},{"latitude":30.825203870634823,"longitude":104.18530025971104},{"latitude":30.82515374687408,"longitude":104.18529810127568},{"latitude":30.825110030854116,"longitude":104.18528821730578},{"latitude":30.82508119601531,"longitude":104.18527128696311},{"latitude":30.825035757025645,"longitude":104.18525706087385},{"latitude":30.824982781979802,"longitude":104.1852384225167},{"latitude":30.824933907572735,"longitude":104.18522067272963},{"latitude":30.824913072527316,"longitude":104.18519538810145},{"latitude":30.82488457701221,"longitude":104.18517349689064},{"latitude":30.824869285329594,"longitude":104.18512630273324},{"latitude":30.824867943153066,"longitude":104.18510533114683},{"latitude":30.824879687811496,"longitude":104.18506826971719},{"latitude":30.82489700712484,"longitude":104.18503036012521},{"latitude":30.824909546819367,"longitude":104.18499081332656},{"latitude":30.8249245971118,"longitude":104.18494083582105},{"latitude":30.82494121645514,"longitude":104.18489185658295},{"latitude":30.824951338531402,"longitude":104.1848448833738},{"latitude":30.8249653402895,"longitude":104.18479382787683},{"latitude":30.82497884731131,"longitude":104.18473977788959},{"latitude":30.824991356131342,"longitude":104.18469532024251},{"latitude":30.825002170762737,"longitude":104.18464720925608},{"latitude":30.825015442908207,"longitude":104.18460119455332},{"latitude":30.825030383777438,"longitude":104.18455095772356},{"latitude":30.825046327227543,"longitude":104.18449963297061},{"latitude":30.82505665052113,"longitude":104.18445214091764},{"latitude":30.825064573665237,"longitude":104.18440401993166},{"latitude":30.825076946802827,"longitude":104.18435182668541},{"latitude":30.82509144230601,"longitude":104.18428274469929},{"latitude":30.82511327597095,"longitude":104.18423312721873},{"latitude":30.825110145925848,"longitude":104.18419429867278},{"latitude":30.825116943954697,"longitude":104.18415949319451},{"latitude":30.825106672249227,"longitude":104.1840923665504},{"latitude":30.82512216536681,"longitude":104.18405201176436},{"latitude":30.82512780323077,"longitude":104.184011556709},{"latitude":30.825136487568,"longitude":104.18396310657813},{"latitude":30.825144629722583,"longitude":104.1839156845453},{"latitude":30.825149426810512,"longitude":104.18388082915875},{"latitude":30.82515605869422,"longitude":104.1838331176265},{"latitude":30.82516498602375,"longitude":104.18377775037591},{"latitude":30.825174529857676,"longitude":104.18372446932695},{"latitude":30.825182915407314,"longitude":104.18367533058917},{"latitude":30.825186394081328,"longitude":104.1836392574722},{"latitude":30.825192353946758,"longitude":104.18359788429126},{"latitude":30.82519410406457,"longitude":104.18355512349315},{"latitude":30.82519027465586,"longitude":104.18350504598816},{"latitude":30.82518687038014,"longitude":104.18345233340543},{"latitude":30.825183570130882,"longitude":104.18341908480983},{"latitude":30.825169827528853,"longitude":104.18336239913445},{"latitude":30.8251498148849,"longitude":104.18330387659249},{"latitude":30.825122860744838,"longitude":104.18326568607067},{"latitude":30.825097750474203,"longitude":104.18320977848964},{"latitude":30.825065609846664,"longitude":104.18314658411208},{"latitude":30.825052965884,"longitude":104.1831071965478},{"latitude":30.8250393147554,"longitude":104.18305520233416},{"latitude":30.825026058701557,"longitude":104.18301677299489},{"latitude":30.825019362211467,"longitude":104.1829805399064},{"latitude":30.82502691145921,"longitude":104.1829562453525},{"latitude":30.825064927670894,"longitude":104.1829318923672},{"latitude":30.825075469771622,"longitude":104.18289617916396},{"latitude":30.825107722451296,"longitude":104.18287740555756},{"latitude":30.825142436080217,"longitude":104.18286963164859},{"latitude":30.825160869972777,"longitude":104.18285147623878},{"latitude":30.825196479856682,"longitude":104.18282443814745},{"latitude":30.825254219296454,"longitude":104.18275575846747},{"latitude":30.825318470953746,"longitude":104.18272553767972},{"latitude":30.825406040737647,"longitude":104.18273020319388},{"latitude":30.82545034860031,"longitude":104.18270685868356},{"latitude":30.82547974855814,"longitude":104.18266179383048},{"latitude":30.825533003273247,"longitude":104.18263743165275},{"latitude":30.82558979534643,"longitude":104.18262631502792},{"latitude":30.8256558020132,"longitude":104.18261008834328},{"latitude":30.825715547012223,"longitude":104.18258751316421},{"latitude":30.8257600814258,"longitude":104.18258225506672},{"latitude":30.82580208390659,"longitude":104.18258266630828},{"latitude":30.825862828804297,"longitude":104.18258736048247},{"latitude":30.825904379557585,"longitude":104.1826101001936},{"latitude":30.8259431814626,"longitude":104.18261525246929},{"latitude":30.826000622141855,"longitude":104.18264815405743},{"latitude":30.826058414055897,"longitude":104.18266434672313},{"latitude":30.826123190571895,"longitude":104.18267476046384},{"latitude":30.82614927473916,"longitude":104.18268029143118},{"latitude":30.826218521628928,"longitude":104.18269722327481},{"latitude":30.82625794232072,"longitude":104.18273014398966},{"latitude":30.82630097697823,"longitude":104.18274046686658},{"latitude":30.826348473035836,"longitude":104.18276213887455},{"latitude":30.826387781490247,"longitude":104.18276930743562},{"latitude":30.826436462336037,"longitude":104.18277798364429},{"latitude":30.82649529239735,"longitude":104.18280088391923},{"latitude":30.826547984049032,"longitude":104.18282109889242},{"latitude":30.82658476243342,"longitude":104.18283832865254},{"latitude":30.82661351480575,"longitude":104.18285101646556},{"latitude":30.826655728137617,"longitude":104.18285642843242},{"latitude":30.8267040135787,"longitude":104.18288406941774},{"latitude":30.82676196019568,"longitude":104.18289779670026},{"latitude":30.82680323007917,"longitude":104.18291556568535},{"latitude":30.826839642312027,"longitude":104.18293600947642},{"latitude":30.826863829982216,"longitude":104.1829660448864},{"latitude":30.82688249849348,"longitude":104.18300476392788},{"latitude":30.82688463334171,"longitude":104.18304591767638},{"latitude":30.82688298529683,"longitude":104.18309290044793},{"latitude":30.826878294687347,"longitude":104.18313497220056},{"latitude":30.826869690593533,"longitude":104.1831669724549},{"latitude":30.826859740563535,"longitude":104.18319098745728},{"latitude":30.82685552933082,"longitude":104.1832065783543},{"latitude":30.826863616297803,"longitude":104.18322142122727},{"latitude":30.82687135212636,"longitude":104.18321519314097},{"latitude":30.82687166225206,"longitude":104.18322061310936},{"latitude":30.826875269186434,"longitude":104.18325571821741},{"latitude":30.826878829704146,"longitude":104.18329427693521},{"latitude":30.826879305047065,"longitude":104.1833347120432},{"latitude":30.82687528828061,"longitude":104.18338034732025},{"latitude":30.82686613101035,"longitude":104.18343012470127},{"latitude":30.826844876950187,"longitude":104.1834907614255},{"latitude":30.826844034408253,"longitude":104.18355669934866},{"latitude":30.826838306433434,"longitude":104.18361872431775},{"latitude":30.826832975419002,"longitude":104.18368252605627},{"latitude":30.82682629972719,"longitude":104.18374306380332},{"latitude":30.82683023993625,"longitude":104.18380901209282},{"latitude":30.82683061999407,"longitude":104.18387940204842},{"latitude":30.82683072222164,"longitude":104.18394314431525},{"latitude":30.826821151911812,"longitude":104.18401078895545},{"latitude":30.826804516236766,"longitude":104.18406841179849},{"latitude":30.82679700105569,"longitude":104.18413393054193},{"latitude":30.82679102832806,"longitude":104.18419860096594},{"latitude":30.82678429532214,"longitude":104.18426321150567},{"latitude":30.82677632011528,"longitude":104.18432324047168},{"latitude":30.826767772428088,"longitude":104.18438445725818},{"latitude":30.8267647703633,"longitude":104.18444430686527},{"latitude":30.826757985164345,"longitude":104.18450473526254},{"latitude":30.82675516221526,"longitude":104.18457057392834},{"latitude":30.82674951884976,"longitude":104.18463038359664},{"latitude":30.826746208713068,"longitude":104.18469458533508},{"latitude":30.82674057943976,"longitude":104.18475763911623},{"latitude":30.826732765588744,"longitude":104.18482253944084},{"latitude":30.82672351049635,"longitude":104.18488769926415},{"latitude":30.826716286593367,"longitude":104.18494740923816},{"latitude":30.82670060080749,"longitude":104.18500561161412},{"latitude":30.826693741822197,"longitude":104.18506822634926},{"latitude":30.826689031563216,"longitude":104.18513219873815},{"latitude":30.826681999154072,"longitude":104.18519122014015},{"latitude":30.826679294582366,"longitude":104.18524729718439},{"latitude":30.82668442427001,"longitude":104.185308874556},{"latitude":30.82668246756502,"longitude":104.18536636911081},{"latitude":30.826679906264495,"longitude":104.18542619939538},{"latitude":30.826675792876244,"longitude":104.18548126836227},{"latitude":30.82667408939884,"longitude":104.18554257605989},{"latitude":30.826663531820483,"longitude":104.1855980141153},{"latitude":30.826657957486017,"longitude":104.18565320289868},{"latitude":30.826644559787987,"longitude":104.18569697222156},{"latitude":30.826618876938497,"longitude":104.18572894254814},{"latitude":30.826594943202743,"longitude":104.18575102104921},{"latitude":30.82656643171493,"longitude":104.18575958403845},{"latitude":30.826538892478318,"longitude":104.1857617587502},{"latitude":30.826515217327245,"longitude":104.18574105546178},{"latitude":30.826488768777796,"longitude":104.18572137018485},{"latitude":30.826466278854063,"longitude":104.18570363154203},{"latitude":30.826440366764192,"longitude":104.185686042466},{"latitude":30.82642285876599,"longitude":104.18567421326142},{"latitude":30.826399403265643,"longitude":104.18566467957676},{"latitude":30.82636838740781,"longitude":104.18565305934845},{"latitude":30.82633842250468,"longitude":104.18565213960123},{"latitude":30.826312110905917,"longitude":104.18565052130582},{"latitude":30.826292961715804,"longitude":104.18564975179974},{"latitude":30.826263015170998,"longitude":104.1856388303463},{"latitude":30.826236820979293,"longitude":104.18562775934672},{"latitude":30.826205474449857,"longitude":104.18561640861444},{"latitude":30.826164018150173,"longitude":104.18560188320915},{"latitude":30.826126706839585,"longitude":104.18558589068817},{"latitude":30.82607894841265,"longitude":104.1855706263393},{"latitude":30.826028790784115,"longitude":104.18555965402437},{"latitude":30.82598453598697,"longitude":104.18554347152732},{"latitude":30.825935354640734,"longitude":104.18552392495538},{"latitude":30.825875739948337,"longitude":104.18549761027938},{"latitude":30.82579019709216,"longitude":104.18546793053524},{"latitude":30.825749585019953,"longitude":104.18544047886404},{"latitude":30.825678058483543,"longitude":104.18542792843546},{"latitude":30.82561927292242,"longitude":104.18541324252755},{"latitude":30.82557085667605,"longitude":104.18539661068104},{"latitude":30.82552232857448,"longitude":104.18538095704022},{"latitude":30.825484632445445,"longitude":104.18536204987953},{"latitude":30.825450832449498,"longitude":104.18535186692368},{"latitude":30.82539043253865,"longitude":104.18533362746234},{"latitude":30.825329540709575,"longitude":104.18531628633487},{"latitude":30.825276947940967,"longitude":104.185307400111},{"latitude":30.825219973545508,"longitude":104.1852817543969},{"latitude":30.82516994161272,"longitude":104.18523509754199},{"latitude":30.825119833749042,"longitude":104.18521341490833},{"latitude":30.825060151402813,"longitude":104.18519129262923},{"latitude":30.825000495956083,"longitude":104.18517630726654},{"latitude":30.824959543279515,"longitude":104.1851545651924},{"latitude":30.824938514834074,"longitude":104.18513651729675},{"latitude":30.82490605519584,"longitude":104.18511024395099},{"latitude":30.824893006547512,"longitude":104.1850566516755},{"latitude":30.82490596394288,"longitude":104.18503478243477},{"latitude":30.824934504782963,"longitude":104.1849722486057},{"latitude":30.82495562928725,"longitude":104.18492181224272},{"latitude":30.824964865287285,"longitude":104.18486700337338},{"latitude":30.824978823831593,"longitude":104.18481224466883},{"latitude":30.82500239674866,"longitude":104.18474172543233},{"latitude":30.82502156305753,"longitude":104.18467349183315},{"latitude":30.82502370093556,"longitude":104.18461016843436},{"latitude":30.825038728583916,"longitude":104.1845291582502},{"latitude":30.82506279752558,"longitude":104.18444476479584},{"latitude":30.82508191010054,"longitude":104.18438946756822},{"latitude":30.825084090723415,"longitude":104.1843247469302},{"latitude":30.825094334792784,"longitude":104.184255175662},{"latitude":30.82511896419075,"longitude":104.1841816324546},{"latitude":30.825135326296483,"longitude":104.18413665620032},{"latitude":30.825150902150334,"longitude":104.1840569440327},{"latitude":30.825170147061385,"longitude":104.18398968910205},{"latitude":30.825179229283325,"longitude":104.18391004661044},{"latitude":30.825180118213673,"longitude":104.18384057499544},{"latitude":30.82518558447452,"longitude":104.18376852840504},{"latitude":30.82520594012592,"longitude":104.18369047368498},{"latitude":30.82520473532006,"longitude":104.18362785943098},{"latitude":30.825200496314718,"longitude":104.1835666225205},{"latitude":30.825188665780438,"longitude":104.18350395792528},{"latitude":30.825177177423022,"longitude":104.18344023534182},{"latitude":30.82517323211706,"longitude":104.18338253200793},{"latitude":30.825162546758868,"longitude":104.18333365203716},{"latitude":30.825137292324154,"longitude":104.18328533035819},{"latitude":30.82511392558075,"longitude":104.18321724542128},{"latitude":30.82508412961031,"longitude":104.1831630245138},{"latitude":30.82505757094034,"longitude":104.18311662927456},{"latitude":30.825037092556563,"longitude":104.18307190125246},{"latitude":30.825015814626898,"longitude":104.18301052409984},{"latitude":30.825021191092738,"longitude":104.1829762978657},{"latitude":30.825004306088566,"longitude":104.18294701141062},{"latitude":30.825051103217298,"longitude":104.18290861491496},{"latitude":30.8250891000651,"longitude":104.18290547256274},{"latitude":30.825127524497553,"longitude":104.18291453757027},{"latitude":30.82516144742822,"longitude":104.18290690336164},{"latitude":30.825208854870624,"longitude":104.18290624684428},{"latitude":30.82525736812192,"longitude":104.18288123559321},{"latitude":30.825293922781558,"longitude":104.18285729179456},{"latitude":30.825344401276467,"longitude":104.18281388481032},{"latitude":30.825386156675524,"longitude":104.18279109912316},{"latitude":30.825412246648078,"longitude":104.18278811591007},{"latitude":30.825485303478146,"longitude":104.18275234584313},{"latitude":30.825533566780813,"longitude":104.18273263476681},{"latitude":30.82559543243199,"longitude":104.18268878918863},{"latitude":30.825651151485715,"longitude":104.182657440108},{"latitude":30.825719478704784,"longitude":104.18263622280578},{"latitude":30.82578881190567,"longitude":104.18261747097254},{"latitude":30.82585069949445,"longitude":104.18262105726204},{"latitude":30.825905957010526,"longitude":104.18264962679896},{"latitude":30.825975289361015,"longitude":104.18265825407614},{"latitude":30.826039797087002,"longitude":104.18267331915945},{"latitude":30.826103654900763,"longitude":104.18269891464597},{"latitude":30.826170313945116,"longitude":104.18270852996318},{"latitude":30.826229160522495,"longitude":104.18272791675307},{"latitude":30.82629125766501,"longitude":104.18275874245136},{"latitude":30.826348334365335,"longitude":104.18277754025904},{"latitude":30.82640456633995,"longitude":104.18279863376557},{"latitude":30.826455917993872,"longitude":104.18281305942605},{"latitude":30.82651242649779,"longitude":104.18283610931923},{"latitude":30.826570779607106,"longitude":104.18285184289013},{"latitude":30.826625102633663,"longitude":104.18287180841325},{"latitude":30.826684518391353,"longitude":104.18289182408994},{"latitude":30.826742442310287,"longitude":104.18290699868555},{"latitude":30.82680002191273,"longitude":104.18291900914014},{"latitude":30.826844472059648,"longitude":104.18294297677521},{"latitude":30.826878819838853,"longitude":104.18296520715694},{"latitude":30.826912562213046,"longitude":104.18299017243908},{"latitude":30.826933670796492,"longitude":104.18300802032932},{"latitude":30.826953077106516,"longitude":104.1830265868079},{"latitude":30.826973084807342,"longitude":104.18304458437366},{"latitude":30.826968408273693,"longitude":104.18307367019547},{"latitude":30.826963161920055,"longitude":104.183091706491},{"latitude":30.826905086378535,"longitude":104.18319061032169},{"latitude":30.826878559377278,"longitude":104.18327278674359},{"latitude":30.826869653772043,"longitude":104.18335410565686},{"latitude":30.826865996613844,"longitude":104.18341626036764},{"latitude":30.8268658713835,"longitude":104.18347844522694},{"latitude":30.826863887323924,"longitude":104.18355566221568},{"latitude":30.826856355511314,"longitude":104.18362462426535},{"latitude":30.82685574478665,"longitude":104.18368968390661},{"latitude":30.826842943594208,"longitude":104.18375676926134},{"latitude":30.82684540712676,"longitude":104.18382048162088},{"latitude":30.826842533763894,"longitude":104.1838971598129},{"latitude":30.826839561386155,"longitude":104.18397329905221},{"latitude":30.826835454076807,"longitude":104.18405720396063},{"latitude":30.826835997590848,"longitude":104.18413125733515},{"latitude":30.826822812729368,"longitude":104.18419491927314},{"latitude":30.826813468539054,"longitude":104.18427563998527},{"latitude":30.826802743137783,"longitude":104.18435121018766},{"latitude":30.826787924646894,"longitude":104.1844218293721},{"latitude":30.826776500233613,"longitude":104.18449670093922},{"latitude":30.82677149348496,"longitude":104.18456936692922},{"latitude":30.826771018926962,"longitude":104.18463680281214},{"latitude":30.826770220129017,"longitude":104.18470103461934},{"latitude":30.82677348319075,"longitude":104.1847654962407},{"latitude":30.82677320984726,"longitude":104.18484325330293},{"latitude":30.82677079239203,"longitude":104.18490632729835},{"latitude":30.8267609361482,"longitude":104.18497195628905},{"latitude":30.826751699302505,"longitude":104.18504355439819},{"latitude":30.826743582132394,"longitude":104.18511025160787},{"latitude":30.82673905623482,"longitude":104.18518279830818},{"latitude":30.826731649093656,"longitude":104.18524429518598},{"latitude":30.826727532527855,"longitude":104.1853119310111},{"latitude":30.826722035723733,"longitude":104.18537385727998},{"latitude":30.82671824326135,"longitude":104.18543939705494},{"latitude":30.826715067778387,"longitude":104.18549589346144},{"latitude":30.826705496748442,"longitude":104.18555349757114},{"latitude":30.826694840383254,"longitude":104.18559734682958},{"latitude":30.82668742841558,"longitude":104.1856452388701},{"latitude":30.826677293138705,"longitude":104.18568321893036},{"latitude":30.826663472735497,"longitude":104.18573379580359},{"latitude":30.82665214221912,"longitude":104.18575247112715},{"latitude":30.826625365890333,"longitude":104.18576419841605},{"latitude":30.826597096258844,"longitude":104.18576091307206},{"latitude":30.82656213910321,"longitude":104.18574880353763},{"latitude":30.826519673985803,"longitude":104.18573876985222},{"latitude":30.8264764670865,"longitude":104.18571312467213},{"latitude":30.826431398861722,"longitude":104.18569854917052},{"latitude":30.826391402344612,"longitude":104.18567912278333},{"latitude":30.826351391231274,"longitude":104.18566765185106},{"latitude":30.826314323708317,"longitude":104.18565511301371},{"latitude":30.82627275741657,"longitude":104.18564599770197},{"latitude":30.82622487150839,"longitude":104.18562931592949},{"latitude":30.826166841270737,"longitude":104.18561193495526},{"latitude":30.82610339019918,"longitude":104.18557702579578},{"latitude":30.826057700307047,"longitude":104.18554138882902},{"latitude":30.82600661014997,"longitude":104.1855042743234},{"latitude":30.825965548937567,"longitude":104.18549255382011},{"latitude":30.825913497289175,"longitude":104.18547775842356},{"latitude":30.825884563347884,"longitude":104.18546028902831},{"latitude":30.825853137950617,"longitude":104.1854483094647},{"latitude":30.825815483745487,"longitude":104.18543380423077},{"latitude":30.82578727050409,"longitude":104.18541617517076},{"latitude":30.825753653955253,"longitude":104.18540416556343},{"latitude":30.825718168152115,"longitude":104.18539118764224},{"latitude":30.825676692326706,"longitude":104.18538186274515},{"latitude":30.825630230333957,"longitude":104.18537439421036},{"latitude":30.8255816294144,"longitude":104.1853656978236},{"latitude":30.825537562219317,"longitude":104.18534545281342},{"latitude":30.825487370766208,"longitude":104.18533112666944},{"latitude":30.825442842296685,"longitude":104.18531144062048},{"latitude":30.825397806995113,"longitude":104.1852844379621},{"latitude":30.82534998353911,"longitude":104.18526647860064},{"latitude":30.825294595205378,"longitude":104.185248898187},{"latitude":30.825244743278176,"longitude":104.18523494139696},{"latitude":30.825195583497806,"longitude":104.18522002639901},{"latitude":30.82514119947323,"longitude":104.18520584980013},{"latitude":30.82509337184832,"longitude":104.18519016627981},{"latitude":30.82504636025519,"longitude":104.1851768883889},{"latitude":30.825003597692533,"longitude":104.1851654173883},{"latitude":30.824955702295696,"longitude":104.18514850612371},{"latitude":30.824915251440945,"longitude":104.18513136563786},{"latitude":30.824888958179187,"longitude":104.18511435559128},{"latitude":30.82487540048013,"longitude":104.18509271465302},{"latitude":30.82486892481606,"longitude":104.18506666215399},{"latitude":30.824883845282415,"longitude":104.18502740492202},{"latitude":30.824898271245605,"longitude":104.18499045344934},{"latitude":30.824909977785296,"longitude":104.18494694390549},{"latitude":30.824930284567078,"longitude":104.18489503023095},{"latitude":30.824950460743754,"longitude":104.1848325559859},{"latitude":30.82496927424864,"longitude":104.18478199980726},{"latitude":30.824998565020977,"longitude":104.18473065560435},{"latitude":30.825006846863705,"longitude":104.1846778630904},{"latitude":30.82502361306823,"longitude":104.18461441062432},{"latitude":30.825033419270987,"longitude":104.18456516172435},{"latitude":30.82504781435612,"longitude":104.18450705936831},{"latitude":30.825060140131352,"longitude":104.18445339876762},{"latitude":30.825077947597066,"longitude":104.18439505708156},{"latitude":30.825087040358984,"longitude":104.18435292514302},{"latitude":30.82509558954911,"longitude":104.18432882995413},{"latitude":30.82510008091804,"longitude":104.18430775900326},{"latitude":30.825091744514506,"longitude":104.18428705676493}],"scoringType":1,"semesterId":"8a97807a907736810191793a841a36f4","signDigital":"2e88546898b5f1c3d824b871f84d09d4b5c93482","signPoint":[],"signTime":"2024-09-20 06:30:52","startTime":"2024-09-20 06:27:07","systemVersion":"13","totalMileage":1.0202,"totalPart":0.0,"type":"范围跑","uneffectiveReason":""}
    oct={
	"rt":	"范围跑",
	"lcs":	1.5112,
	"bs":	0,
	"bf":	0,
	"zlc":	1.5112,
	"tp":	0,
	"em":	1.23,
	"ep":	1,
	"uer":	"",
	"st":	"2024-09-19 15:54:48",
	"et":	"2024-09-19 16:00:53",
	"kill":	90,
	"ap":	237665,
	"xq":	"8a97807a907736810191793a841a36f4",
	"jf":	1,
	"lid":	"402888da7c3a16bb017c3a17044e000f",
	"sv":	"13",
	"app":	"3.10.0",
	"dt":	"google Pixel 6 Pro",
	"kt":	990
}
   
    info["effectiveMileage"]=mileage#有效里程
    info["totalMileage"]=mileage
    info["gpsMileage"]=mileage

    # info["effectivePart"]="1"#有效部分
    # info["startTime"]="2024-04-24 18:24:21"#活动开始时间
    # info["calorie"]="24"#消耗的卡路里
    # info["avePace"]="39.0"#平均配速
    # info["keepTime"]="600"#活动持续时间
    # info["paceNumber"]="0"#配速数量
    # info["totalMileage"]="0.2694"#totalMileage
    # info["totalPart"]="0.0"#总部分


    #实现数据浮动
    info["calorie"]=info["calorie"]+random.randint(1,5)
    #info["paceNumber"]=info["paceNumber"]+random.randint(5,15)
    info["endTime"]=accepttime()
    info["keepTime"]=int(random.randint(900,1200)/110)*110
    info["avePace"]=info["avePace"]-100*info["keepTime"]
    info["signTime"]=info["endTime"]
    avePace_float = float(info["avePace"])
    totalPart_float = float(info["totalPart"])
    #时间
    time_minute=int(info["keepTime"]/60)
    time_second=info["keepTime"]%60
    info["startTime"]=acceptEndtime(info["endTime"],time_minute,time_second)
    
    print("持续时间: ",info["keepTime"],"s  开始时间：",info["startTime"],"  结束时间：",info["endTime"],"  平均速度:  ",info["avePace"])
    oct["lcs"]=mileage
    oct["zlc"]=mileage
    oct["em"]=mileage
    oct["st"]=info["startTime"]
    oct["et"]=info["endTime"]
    oct["ap"]=info["avePace"]
    oct["kill"]=info["calorie"]
    print(info["keepTime"])
    oct["kt"]=info["keepTime"]
    ##########主要加密部分

    total=str(info["effectiveMileage"])+str(info["effectivePart"])+info["startTime"]+str(info["calorie"])+str(int(avePace_float))+str(info["keepTime"])+str(info["paceNumber"])+str(info["totalMileage"])+str(int(totalPart_float))
    print("加密前的签名： ",total) 
    oct_text ="{\n" + \
           "\t\"rt\":\t\"{}\",\n".format(oct["rt"]) + \
           "\t\"lcs\":\t{},\n".format(oct["lcs"]) + \
           "\t\"bs\":\t{},\n".format(oct["bs"]) + \
           "\t\"bf\":\t{},\n".format(oct["bf"]) + \
           "\t\"zlc\":\t{},\n".format(oct["zlc"]) + \
           "\t\"tp\":\t{},\n".format(oct["tp"]) + \
           "\t\"em\":\t{},\n".format(oct["em"]) + \
           "\t\"ep\":\t{},\n".format(oct["ep"]) + \
           "\t\"uer\":\t\"{}\",\n".format(oct["uer"]) + \
           "\t\"st\":\t\"{}\",\n".format(oct["st"]) + \
           "\t\"et\":\t\"{}\",\n".format(oct["et"]) + \
           "\t\"kill\":\t{},\n".format(oct["kill"]) + \
           "\t\"ap\":\t{},\n".format(oct["ap"]) + \
           "\t\"xq\":\t\"{}\",\n".format(oct["xq"]) + \
           "\t\"jf\":\t{},\n".format(oct["jf"]) + \
           "\t\"lid\":\t\"{}\",\n".format(oct["lid"]) + \
           "\t\"sv\":\t\"{}\",\n".format(oct["sv"]) + \
           "\t\"app\":\t\"{}\",\n".format(oct["app"]) + \
           "\t\"dt\":\t\"{}\",\n".format(oct["dt"]) + \
           "\t\"kt\":\t{}\n".format(oct["kt"]) + \
           "}"   


    info["oct"]= encrypt_aes_ecb(oct_text,Key)
    print("加密后的oct：",info["oct"])
    print("解密后的oct：",decrypt_aes_ecb(info["oct"],Key))
   ######################

    #PRC注入
    # device=frida.get_device_manager().add_remote_device("10.101.2.168:2333")
    # session=device.attach("com.ledreamer.zz")
    # with open("D:\\jsproject\\te.js") as f:
    #     script=session.create_script(f.read())
    # script.load()
    # api=script.exports_sync
    # print("before_encode_result: "+total)

    info["signDigital"]=encode(total)
    print("加密后的签名： ",info["signDigital"])
    print("发送的包：",info)
    return info


def accepttime():
    current_time = datetime.now()
    current_time_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
    return current_time_str


def acceptEndtime(start_time_str,minute,second):
    # 将时间字符串解析为 datetime 对象
    start_time = datetime.strptime(start_time_str, '%Y-%m-%d %H:%M:%S')
    # 增加十分钟

    new_time = start_time - timedelta(minutes=minute)-timedelta(seconds=second)
    # 将新的时间对象转换为字符串并返回
    return new_time.strftime('%Y-%m-%d %H:%M:%S')
def format_string_with_newlines(input_string):
    # 每 76 个字符分段
    chunk_size = 76
    formatted_string = ""
    
    for i in range(0, len(input_string), chunk_size):
        # 取出当前段落
        chunk = input_string[i:i + chunk_size]
        # 添加到结果中并换行
        formatted_string += chunk + "\n"
    
    return formatted_string

def login(user):
    session=requests.session()
    ur1="https://cpes.legym.cn/authorization/user/v2/manage/login"
    header={
        "user-agent":"Mozilla/5.0 (Linux; Android 13; HuaWei P30 Build/SP1A.210812.016.C2; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/123.0.6312.40 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/48.857143)",
        "Content-Type":"application/json"
    }
    print("登录乐健体育ing。。。")
    data={
        
	"entrance": "1",
	"password": user["password"],
	"userName": user["username"],
	"signDigital": encodeuser(user["username"],user["password"])
    }
    new_data={"entrance":"1","password":"Qq1054799863","phone":"15130009576","signDigital":"","userName":"15130009576","authType":"Bearer","baseUrl":"https://cpes.legym.cn/","page":"","type":""}
    json_data={"t": 123,"pyd":"12344"}
    new_data["password"]=data["password"]
    new_data["phone"]=data["userName"]
    new_data["userName"]=data["userName"]
    new_data["signDigital"]=data["signDigital"]
    json_data["t"]=int(datetime.now().timestamp() * 1000)
    print("当前时间戳",json_data["t"],"Key:",login_get_key(str(json_data["t"])))

    json_data_text=json.dumps(new_data)
    
    json_data["pyd"]= encrypt_aes_ecb(json_data_text,login_get_key(str(json_data["t"])))
    print(json_data)
    responseRes = session.post(ur1, json=json_data, headers=header,verify=False)
    response_data=responseRes.json()

    return response_data

def Upinfo(pyc,data):
    token = pyc["accessToken"]
    session = requests.session()
    ur1 = "https://cpes.legym.cn/running/app/v3/upload"
    toke = "Bearer " + token
    header = {
        "method":"POST",
        "path": "/running/app/v3/upload",
        "authority":"cpes.legym.cn",
        "scheme": "https",
        "charset":"UTF-8",
        "authorization": toke,
        "content-type": "application/json",
        "accept-encoding":"gzip"
    }
    print("请求头：",header)
    responseRes = session.post(ur1, json=data, headers=header)

    # 获取响应体并输出

    responsedata = responseRes.json()
    print("Success")
    print("Response data:", responsedata)



# ...（其他代码保持不变，仅修改主程序部分）

if __name__=="__main__":
    # 用户列表（替换为你的实际用户信息）
    users = [
        {"user": "用户1", "username": "15181662271", "password": "zhaowenjie22!"},
    ]

    for user in users:
        print("\n当前用户：", user["user"])
        try:
            # 固定上传3公里（注意平台规则，确保不超过单日限制）
            Mileage = 4.8  # 修改为3.0公里
            Response = login(user)
            print("登录响应：", Response)
            
            # 解密并处理数据
            pyd = decrypt_aes_ecb(Response["data"]["pyd"], login_get_key(str(Response["data"]["t"])))
            pyd_dict = json.loads(pyd)
            
            # 生成跑步数据并上传
            info = getinfo(Mileage, pyd_dict)
            Upinfo(pyd_dict, info)
        except Exception as e:
            print(f"用户 {user['user']} 上传失败: {str(e)}")
            # 可在此处添加日志记录
    
    print("\n所有用户数据已自动上传完成！")